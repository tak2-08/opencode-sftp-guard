// 플러그인 본체(오픈코드 결합부).
//
// 하는 일:
//  1) 초기화 시점에 비밀 파일을 "한 번" 읽고 비밀값을 redact 등록한다(§0).
//  2) SFTP 전송 계층·승인 게이트·감사 로그를 플러그인 클로저 안에서만 생성한다.
//  3) permission.asked / permission.replied 이벤트를 관찰해 게이트 실측성을 판단한다(gate.ts (A)).
//  4) 방어심겹 훅(§0 "hooks are not the gate"): 지역 비밀 파일을 모델이 못 읽게 한다.
//     + 이 플러그인의 sftp_* 툴을 다른(비허용) 에이전트가 쓸 때 경고한다.
//     → 게이트 자체는 절대 훅에 두지 않는다. 각 툴의 execute 가 직접 부른다.
import { tool } from "@opencode-ai/plugin";
import { AuditLog, defaultAuditPath } from "../core/audit.mjs";
import { ConfigError, DEFAULT_CONFIG_PATH, DEFAULT_SECRETS_PATH, describeConfig, loadPolicy, loadSecrets } from "../core/config.mjs";
import { SftpTransport } from "../core/remote.mjs";
import { listSecretLabels, registerSecret, safeErrorMessage, scrubText } from "../core/redact.mjs";
import { ApprovalGate } from "./gate";
import { SessionState, createTools } from "./tools";

/** 이 플러그인이 소유하는 툴 이름. */
const OWNED_TOOLS = new Set([
  "sftp_list",
  "sftp_read",
  "sftp_stat",
  "sftp_write_new",
  "sftp_edit_existing",
  "sftp_delete",
  "sftp_move",
  "sftp_mkdir",
  "sftp_chmod",
  "sftp_propose_scope",
  "sftp_request_scope_approval",
  "sftp_set_mode",
  "sftp_doctor",
]);

/** 세션 상태 저장소(메모리 전용 — §3 4단계). */
class StateStore {
  #sessions = new Map();
  #max = 32;
  get(sessionID: string, agent = "") {
    let s = this.#sessions.get(sessionID);
    if (!s) {
      s = new SessionState(sessionID);
      this.#sessions.set(sessionID, s);
      this.#evict();
    }
    if (agent) s.agent = agent;
    s.lastActivity = Date.now();
    return s;
  }
  peek(sessionID) {
    return this.#sessions.get(sessionID);
  }
  drop(sessionID) {
    this.#sessions.delete(sessionID);
  }
  all() {
    return Array.from(this.#sessions.values()).map((s) => s.describe());
  }
  #evict() {
    if (this.#sessions.size <= this.#max) return;
    const sorted = Array.from(this.#sessions.entries()).sort((a, b) => a[1].lastActivity - b[1].lastActivity);
    for (const [id] of sorted.slice(0, sorted.length - this.#max)) this.#sessions.delete(id);
  }
}

/**
 * 플러그인 팩토리.
 * @param {any} input PluginInput
 */
export function createSftpGuard(input) {
  const client = input?.client;
  const directory = input?.directory ?? process.cwd();
  const log = (level: string, message: string, extra?: any) => {
    // opencode 구조화 로그로만 남긴다. 콘솔/트랜스크립트로 새지 않는다.
    try {
      void client?.app?.log?.({
        body: {
          service: "sftp-guard",
          level: level === "error" ? "error" : level === "warn" ? "warn" : level === "debug" ? "debug" : "info",
          message: scrubText(message).slice(0, 1_000),
          extra: extra ? scrubText(safeErrorMessage(JSON.stringify(extra))).slice(0, 1_000) : undefined,
        },
      });
    } catch {
      /* 로깅 실패는 무시 */
    }
  };

  // ── 1) 설정/비밀 로드(한 번) ────────────────────────────────────────────────
  const secretsPath = process.env.SFTP_GUARD_SECRETS_PATH || DEFAULT_SECRETS_PATH();
  const configPath = process.env.SFTP_GUARD_CONFIG_PATH || DEFAULT_CONFIG_PATH();
  let policy: any;
  let loaded: any;
  let configSummary: any;
  try {
    loaded = loadSecrets(secretsPath);
    policy = loadPolicy(configPath);
    configSummary = describeConfig(loaded, policy);
    // §0: 비밀 파일 경로 자체도 로그에 남으면 안 된다(경로가 곧 힌트다).
    registerSecret(secretsPath, "sftp.secretsFilePath");
    registerSecret(configPath, "sftp.configFilePath");
  } catch (err) {
    // 설정 실패는 조용히 넘어가지 않는다: 모든 sftp_* 툴이 "사용 불가"로 실패해야 한다(fail closed).
    const reason = err instanceof ConfigError ? err.message : safeErrorMessage(err);
    log("error", `초기화 실패 — 모든 sftp_* 도구 비활성: ${reason}`);
    return createDisabledPlugin({ reason, log });
  }

  log("info", `초기화 완료 (비밀 출처: 파일, 인증: ${configSummary.auth}, 허용 루트: ${policy.allowedRoots.join(", ")})`);
  log("debug", `등록된 비밀 라벨: ${listSecretLabels().join(", ")}`);

  // ── 2) 클로저 내부 싱글턴 ──────────────────────────────────────────────────
  const audit = new AuditLog({ path: policy.auditPath || defaultAuditPath(), ...policy.audit });
  const transport = new SftpTransport({
    connection: loaded.connection,
    allowedRoots: policy.allowedRoots,
    connectRetries: policy.connectRetries,
    onEvent: (e) => log("debug", `transport: ${e.kind} ${e.message}`),
  });
  const gate = new ApprovalGate({ policy, log, client });
  const state = new StateStore();
  const ctx = {
    client,
    policy,
    audit,
    transport,
    gate,
    log,
    configSummary,
    state: (sessionID: string, agent?: string) => state.get(sessionID, agent),
  };
  const tools = createTools(ctx);

  audit.append({
    sessionID: "-",
    agent: "-",
    tool: "sftp-guard",
    outcome: "init",
    approver: "none",
    auth: configSummary.auth,
    allowedRoots: policy.allowedRoots,
    gate: gate.snapshot(),
  });

  return {
    tool: tools,

    /** 승인 게이트 실측성 관측(§0 (A)). */
    event: async ({ event }: { event: any }) => {
      const t = event?.type;
      if (t === "permission.asked") {
        gate.noteAnyAskedEvent();
        gate.observeAsked(event.properties);
      } else if (t === "permission.replied") {
        gate.observeReplied(event.properties);
      } else if (t === "session.deleted") {
        const id = event?.properties?.info?.id ?? event?.properties?.sessionID;
        if (id) state.drop(id);
      }
    },

    /**
     * 방어심겹 훅. ★ 게이트가 아니다.
     * - 지역 비밀 파일 읽기 차단: 모델이 비밀 파일을 cat 하면 §0 이 깨진다.
     * - sftp_* 툴이 sftp 권한이 없는 다른 에이전트에서 불리는 경우 경고 로그.
     */
    "tool.execute.before": async (input: any, output: any) => {
      const toolName = input?.tool;
      if (toolName === "read" || toolName === "grep" || toolName === "glob" || toolName === "bash" || toolName === "edit" || toolName === "write") {
        const target = String(output?.args?.filePath ?? output?.args?.path ?? output?.args?.pattern ?? output?.args?.command ?? "");
        if (target && /sftp-secrets\.json|sftp-guard\.json/i.test(target)) {
          throw new Error(
            "차단됨: sftp-guard 의 비밀/설정 파일은 모델이 읽을 수 없다(§0 — 자격증명 격리). " +
              "필요한 설정 값은 sftp_doctor 의 구성 요약으로 확인하라.",
          );
        }
      }
      if (OWNED_TOOLS.has(toolName) && input?.sessionID) {
        const s = state.peek(input.sessionID);
        if (s) s.lastActivity = Date.now();
      }
    },

    dispose: async () => {
      try {
        await transport.close();
      } catch {
        /* noop */
      }
      audit.append({ sessionID: "-", agent: "-", tool: "sftp-guard", outcome: "dispose", approver: "none" });
    },
  };
}

/** 설정이 실패했을 때의 플러그인: 모든 sftp_* 툴이 명시적으로 실패한다(도구가 사라지지 않는다). */
function createDisabledPlugin({ reason, log }: { reason: string; log: (lvl: string, m: string, extra?: any) => void }) {
  const out: Record<string, any> = {};
  for (const name of OWNED_TOOLS) {
    out[name] = tool({
      description: `SFTP 도구 ${name} — 현재 비활성(비밀/설정 로드 실패).`,
      args: { reason: tool.schema.string().optional().describe("무시") },
      execute: async () => {
        throw new Error(`sftp-guard 비활성: ${reason}`);
      },
    });
  }
  return { tool: out, event: async () => {}, dispose: async () => log("info", "sftp-guard dispose(비활성 상태)") };
}

export { createDisabledPlugin };
