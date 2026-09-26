// 승인 게이트 — §0 "Enforcement lives inside each tool's execute()" + §5 승인 UX.
//
// 이 모듈이 §0 의 핵심 계약을 구현한다:
//
//  (A) 게이트 실측성(liveness) 검증 — opencode 1.18.22 의 기본 permission 설정은
//      `{ "*": "allow" }` 이다(실측: opencode.exe 내부 기본값). 따라서 context.ask() 는
//      "설정으로 ask 가 지정되어 있지 않으면" 조용히 통과해 버린다(=승인 우회).
//      이 플러그인은 ask() 를 호출한 뒤 permission.asked 이벤트가 실제로 관측되었는지 확인하고,
//      관측되지 않았다면 "게이트가 죽어 있다"로 판정해 DENY 한다(fail closed).
//      → 운영자가 opencode.json / agent frontmatter 에 sftp_* 규칙을 추가해야만 동작한다.
//      README 에 정확한 설정 줄을 적어 두었다.
//
//  (B) 한 세션에 동시 승인 요청 1개 — opencode 의 reject 는 같은 세션의 다른 대기 요청을
//      전부 거부시켜 버린다(permission/index.ts reply()). 동시 요청을 직렬화해 의도치 않은 연쇄 거부를
//      막는다. 특히 게이트가 아니라 §3 범위 승인이 묶여 죽지 않게 한다.
//
//  (C) 타임아웃 = DENY — 사람이 오프라인이면 세션이 영원히 뜨지 않는다(§7).
//      타임아웃 시 추적해 둔 permission id 로 서버에 reject 를 보내 abandoning 없이 정리한다.
//
//  (D) 비밀은 이 계층을 통과하지 못한다 — 승인이 유발하는 모든 문자열은 redact 후에만 나간다.
import { randomToken } from "../core/util.mjs";
import { scrubText, safeErrorMessage } from "../core/redact.mjs";
import { APPROVER } from "../core/audit.mjs";

/** 세션별 직렬화 큐. */
class Mutex {
  #tail = new Map();
  async run(key, fn) {
    const prev = this.#tail.get(key) ?? Promise.resolve();
    let release;
    const current = new Promise((r) => {
      release = r;
    });
    this.#tail.set(
      key,
      prev.then(() => current, () => current),
    );
    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

export class ApprovalGate {
  policy: any;
  log: (level: string, msg: string, extra?: any) => void;
  client: any;
  mutex: Mutex;
  /** token → { id, sessionId, permission, askedAt, repliedAt, response, live } */
  pending: Map<string, { id: string | null; sessionId: string; permission: string; askedAt: number; repliedAt: number; response: string | null; live: boolean }>;
  stats: { asks: number; approved: number; rejected: number; timeouts: number; bypassDetected: number; errors: number };
  #sawAnyAskedEvent = false;

  /**
   * @param {{policy: any, log: (level: string, msg: string, extra?: any) => void, client?: any}} deps
   */
  constructor(deps: { policy: any; log?: (level: string, msg: string, extra?: any) => void; client?: any }) {
    this.policy = deps.policy;
    this.log = deps.log ?? (() => {});
    this.client = deps.client;
    this.mutex = new Mutex();
    this.pending = new Map();
    this.stats = { asks: 0, approved: 0, rejected: 0, timeouts: 0, bypassDetected: 0, errors: 0 };
  }

  /**
   * opencode permission.asked 이벤트 관측(플러그인 event 훅에서 호출).
   * metadata.sftpGuardToken 으로 자기 요청과 상관시킨다.
   */
  observeAsked(props) {
    if (!props || typeof props !== "object") return;
    const token = props?.metadata?.sftpGuardToken;
    if (typeof token !== "string" || !this.pending.has(token)) return;
    const entry = this.pending.get(token);
    entry.id = props.id ?? null;
    entry.askedAt = Date.now();
    entry.live = true;
    entry.permission = props.permission ?? entry.permission;
  }

  /** opencode permission.replied 이벤트 관측. */
  observeReplied(props) {
    if (!props || typeof props !== "object") return;
    const id = props.permissionID ?? props.permissionId;
    const sessionId = props.sessionID;
    if (!id) return;
    for (const [token, entry] of this.pending) {
      if (entry.id === id && (sessionId === undefined || entry.sessionId === sessionId)) {
        entry.repliedAt = Date.now();
        entry.response = String(props.response ?? "");
      }
    }
  }

  /**
   * 인간 승인을 요청한다.
   * @param {object} req
   * @param {any} req.context ToolContext
   * @param {string} req.permission PERMISSION.*
   * @param {string[]} req.patterns 승인 UI 에 보여줄 요약(사람이 읽는 문장)
   * @param {object} req.metadata 미리보기(§5: 본문/해시/차이가 반드시 포함되어야 한다)
   * @param {string} req.kind 로깅용 분류
   * @param {string} req.auditContextId 감사 로그 상관관계용
   * @returns {Promise<{ok: boolean, approver?: string, reason: string, requestId?: string, timedOut?: boolean, bypass?: boolean}>}
   */
  async requestHumanApproval(req) {
    const { context, permission, patterns, metadata, kind } = req;
    const token = randomToken(10);
    const entry = {
      id: null,
      sessionId: context.sessionID,
      permission,
      askedAt: 0,
      repliedAt: 0,
      response: null,
      live: false,
    };
    this.pending.set(token, entry);
    this.stats.asks++;

    try {
      // 세션당 동시 요청 1개(opencode 의 reject 연쇄 거부 방지).
      return await this.mutex.run(`ask:${context.sessionID}`, async () => {
        // 승인 전에 사람이 볼 수 있도록 툴 카드 제목을 미리 채운다(§5: 본문 맥락이 먼저 보여야 한다).
        try {
          context.metadata({ title: metadata?.title ?? `SFTP ${permission}`, metadata: { sftpPreview: metadata?.sftpPreview } });
        } catch {
          /* 표시 실패는 승인을 막지 않는다 */
        }

        const askPromise = (async () => {
          try {
            await context.ask({
              permission,
              // 사람이 읽는 미리보기 줄. opencode 의 "always" 규칙 시드로는 쓰지 않는다(§0 참고).
              patterns,
              // ★ 항상 빈 배열: "Allow always" 를 눌러도 어떤 패턴도 영구 허용되지 않는다.
              //   범위/approve-all 확대는 오직 sftp_set_mode(자체 게이트 통과) 경로로만 된다.
              always: [],
              metadata: { ...(metadata ?? {}), sftpGuardToken: token, sftpGuardKind: kind },
            });
            return { ok: true, error: null, feedback: null };
          } catch (err) {
            return { ok: false, error: err, feedback: extractFeedback(err) };
          }
        })();

        const outcome = await this.#race(askPromise, context, entry, req.auditContextId);

        if (outcome.timedOut) {
          this.stats.timeouts++;
          // 추적해 둔 permission id 로 서버에 reject 를 보내 대화상자 고아를 정리한다.
          await this.#cancelRemote(entry);
          const reason = `승인 요청이 ${Math.round(this.policy.approvalTimeoutMs / 1000)}초 내에 응답되지 않아 거부됨(§5/§7 fail-closed).`;
          this.log("warn", `gate timeout kind=${kind} ${req.auditContextId ?? ""}`);
          return { ok: false, approver: APPROVER.NONE, reason, timedOut: true };
        }

        if (outcome.aborted) {
          await this.#cancelRemote(entry);
          return { ok: false, approver: APPROVER.NONE, reason: "세션이 중단(abort)되어 승인 요청을 취소함 — fail-closed." };
        }

        if (!outcome.ok) {
          this.stats.rejected++;
          const feedback = outcome.feedback ? ` (사람의 피드백: ${scrubText(outcome.feedback)})` : "";
          return { ok: false, approver: APPROVER.NONE, reason: `사람이 거부함${feedback}.` };
        }

        // (A) 게이트 실측성 검증: ask() 는 통과했지만 실제로 사람에게 질문이 올라갔는가?
        const liveness = await this.#confirmLiveness(token, entry);
        if (liveness === "dead") {
          this.stats.bypassDetected++;
          const hint = this.#livenessHint(permission);
          this.log("error", `승인 게이트 우회 감지: permission=${permission} (permission.asked 이벤트 없음)`);
          return {
            ok: false,
            approver: APPROVER.NONE,
            bypass: true,
            reason:
              `승인 게이트가 살아 있지 않아 fail-closed 로 거부함. 원인: opencode 의 permission 설정이 ` +
              `이 권한을 allow 로 평가하거나(기본값은 "*": "allow"), --auto 모드다. ` +
              `해결: ${hint}`,
          };
        }
        if (liveness === "unknown") {
          this.log("warn", `승인 이벤트 관측 지연되어 게이트 상태를 확정하지 못함: permission=${permission}`);
          return {
            ok: false,
            approver: APPROVER.NONE,
            reason: "승인 게이트 상태를 확인할 수 없어 fail-closed 로 거부함(관측 지연). 다시 시도할 것.",
          };
        }

        this.stats.approved++;
        const response = entry.response ?? "once";
        this.log("info", `gate approved kind=${kind} permission=${permission} response=${response}`);
        return {
          ok: true,
          approver: APPROVER.HUMAN,
          requestId: entry.id ?? undefined,
          reason: `사람이 승인함 (응답: ${response})`,
        };
      });
    } finally {
      this.pending.delete(token);
    }
  }

  /** 타임아웃/중단 감시와 함께 ask 를 기다린다. */
  async #race(askPromise, context, entry, auditContextId) {
    let timer;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve({ timedOut: true }), this.policy.approvalTimeoutMs);
    });
    let abortHandler;
    const abort = new Promise((resolve) => {
      const signal = context?.abort;
      if (!signal) return;
      if (signal.aborted) {
        resolve({ aborted: true });
        return;
      }
      abortHandler = () => resolve({ aborted: true });
      signal.addEventListener?.("abort", abortHandler, { once: true });
    });
    try {
      const result = await Promise.race([askPromise, timeout, abort]);
      if (result && typeof result === "object" && "ok" in result) return result;
      return result; // { timedOut } 또는 { aborted }
    } finally {
      clearTimeout(timer);
      if (abortHandler) context?.abort?.removeEventListener?.("abort", abortHandler);
      void auditContextId;
    }
  }

  /**
   * liveness 판정: "live" | "dead" | "unknown"
   * ask() 가 끝난 뒤 이벤트가 비동기로 도착할 수 있으므로 짧게 폴링한다.
   */
  async #confirmLiveness(token, entry) {
    const deadline = Date.now() + 2_000;
    for (;;) {
      if (entry.live) return "live";
      if (!this.policy.requireLiveGate) return "live"; // 운영자가 실측성 검사를 끈 경우
      if (Date.now() > deadline) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    // 이벤트 훅이 아예 도달하지 않았을 가능성(플러그인 로드 문제)인지, 아니면 진짜 우회인지 구분한다.
    if (!this.policy.requireLiveGate) return "live";
    if (entry.repliedAt > 0) return "live"; // replied 는 봤는데 asked 를 못 본 경우 = 훅 부분 실패 → 관측 실패로 간주
    return this.#sawAnyAskedEvent ? "unknown" : "dead";
  }

  /** 진단: 플러그인 event 훅이 permission.asked 를 한 번이라도 받았는지. */
  noteAnyAskedEvent() {
    this.#sawAnyAskedEvent = true;
  }

  #livenessHint(permission) {
    return (
      `opencode.json 또는 해당 agent frontmatter 에 ` +
      `"permission": { "${permission}": "ask" } 규칙을 추가하고, --auto 없이 실행하세요. ` +
      `README §5 참고.`
    );
  }

  /** 추적 중인 원격 승인 요청을 reject 로 정리(대화상자 고아 방지). */
  async #cancelRemote(entry) {
    if (!entry.id || !this.client) return;
    try {
      const c: any = this.client;
      if (typeof c.postSessionIdPermissionsPermissionId === "function") {
        await c.postSessionIdPermissionsPermissionId({
          path: { id: entry.sessionId, permissionID: entry.id },
          body: { response: "reject" },
        });
        return;
      }
      if (c.permission?.respond) {
        await c.permission.respond({ sessionID: entry.sessionId, permissionID: entry.id, response: "reject" });
        return;
      }
      if (c.permission?.reply) {
        await c.permission.reply({ requestID: entry.id, reply: "reject" });
      }
    } catch (err) {
      this.log("warn", `원격 승인 요청 정리 실패(무시): ${safeErrorMessage(err)}`);
    }
  }

  /** 진단 스냅샷. */
  snapshot() {
    return {
      stats: { ...this.stats },
      pending: this.pending.size,
      sawAnyAskedEvent: this.#sawAnyAskedEvent,
      requireLiveGate: this.policy.requireLiveGate,
      approvalTimeoutMs: this.policy.approvalTimeoutMs,
    };
  }
}

function extractFeedback(err) {
  if (!err) return null;
  const any: any = err;
  return any?.feedback ?? any?.data?.feedback ?? any?.cause?.feedback ?? null;
}
