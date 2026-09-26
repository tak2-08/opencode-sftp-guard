// 툴 정의 — §0 "Enforcement lives inside each tool's own execute()".
//
// ★ 이 파일의 규칙(컨벤션):
//   모든 툴의 execute() 는 반드시 authorize() 를 "직접" 호출한다.
//   tool.execute.before 같은 훅에 게이트를 두지 않는다(서브에이전트 spawn 경로에서 우회 가능성).
//   훅은 방어심겹(§8 방어심)일 뿐 게이트가 아니다.
//   → 검증: 아래 각 execute 안의 첫 줄이 authorizeGuarded() 이거나 그 직통 경로다.
import { tool } from "@opencode-ai/plugin";
import { APPROVER } from "../core/audit.mjs";
import { ACTION, DECISION, PERMISSION, buildChmodPreview, buildDeletePreview, buildModePreview, buildMovePreview, buildScopePreview, buildWritePreview, decide } from "../core/policy.mjs";
import { RISK, classifyTarget, hasSensitivePathToken, isHardDeniedTarget } from "../core/classify.mjs";
import { buildDiff, diffSummary, applyExactReplaces } from "../core/diff.mjs";
import { guardPath, matchScope, scopeRelative } from "../core/paths.mjs";
import { maskCredentialLikeValues, safeErrorMessage, scrubText } from "../core/redact.mjs";
import { humanBytes, looksBinary, sha256, truncateBytes } from "../core/util.mjs";
import { runAuditor } from "./auditor";

/** 세션 상태 — §3 "in-memory (session-scoped, not persisted to disk)". */
export class SessionState {
  sessionId: string;
  agent = "";
  /** §3 1단계: 사람이 준 base path(탐색 루트). 승인되면 읽기가 자동 허용된다. */
  discoveryRoot: string | null = null;
  /** §3 4단계: 승인된 허용 목록(세션 한정, 메모리 전용). */
  scopePaths: string[] = [];
  approveAll = false;
  auditorMode = false;
  autoApprovedCount = 0;
  /** §4 재시도 상한: 대상 경로+액션별 시도 횟수. */
  attempts = new Map<string, { count: number; auditorDenials: string[] }>();
  touchedPaths = new Set();
  lastActivity = Date.now();

  constructor(sessionId: string) {
    this.sessionId = sessionId;
  }

  bumpAttempt(key) {
    const cur = this.attempts.get(key) ?? { count: 0, auditorDenials: [] };
    cur.count += 1;
    this.attempts.set(key, cur);
    return cur;
  }

  recordAuditorDenial(key, reason) {
    const cur = this.attempts.get(key) ?? { count: 0, auditorDenials: [] };
    cur.auditorDenials.push(reason);
    cur.auditorDenials = cur.auditorDenials.slice(-5);
    this.attempts.set(key, cur);
  }

  describe() {
    return {
      sessionId: this.sessionId,
      agent: this.agent,
      discoveryRoot: this.discoveryRoot,
      scopePaths: [...this.scopePaths],
      approveAll: this.approveAll,
      auditorMode: this.auditorMode,
      autoApprovedCount: this.autoApprovedCount,
      touchedPathCount: this.touchedPaths.size,
    };
  }
}

/**
 * 승인 게이트 호출 + 감사 로그.
 * execute() 안에서만 호출된다.
 *
 * @param {object} args
 * @param {string} args.action ACTION.*
 * @param {any} args.context ToolContext
 * @param {any} args.ctx SftpContext
 * @param {any} [args.classification]
 * @param {any} args.target { requested, resolved, kind, inScope, root }
 * @param {any} [args.preview] { title, patterns, metadata, text }
 * @param {Record<string, any>} [args.audit] 감사 로그에 남길 부가 정보
 * @returns {Promise<{ok: boolean, approver: string, reason: string, gateLog: any[]}>}
 */
async function authorizeGuarded(args) {
  const { action, context, ctx, target } = args;
  const state = ctx.state(context.sessionID, context.agent);
  const policy = ctx.policy;
  const hardDenied = isHardDeniedTarget(args.classification, target?.resolved ?? "");

  const verdict = decide({
    action,
    target,
    classification: args.classification,
    hardDenied,
    session: {
      discoveryRoot: state.discoveryRoot,
      scopePaths: state.scopePaths,
      approveAll: state.approveAll,
      auditorMode: state.auditorMode,
      autoApprovedCount: state.autoApprovedCount,
      // 세션에서 낮춘 상한이 실제로 반영되어야 한다(policy 기본값으로 덮어쓰면 안 된다).
      batchCap: state.batchCap ?? policy.approveAllBatchCap,
    },
    policy,
  });

  const gateLog: any[] = [];
  const baseAudit = {
    sessionID: context.sessionID,
    agent: context.agent,
    action,
    requested: target?.requested,
    resolved: target?.resolved,
    // 승인 범위 기준 상대 경로(로그 가독성. 어떤 scope 항목에 붙는지가 한눈에 보인다).
    scopeRelative:
      target?.resolved && matchScope(state.scopePaths, target.resolved).matched
        ? scopeRelative(matchScope(state.scopePaths, target.resolved).matched, target.resolved)
        : undefined,
    risk: args.classification?.risk ?? RISK.STATIC,
    classification: args.classification?.summary,
    ...(args.audit ?? {}),
  };

  // 1) fail-closed: DENY 는 게이트로 승인을 얻을 수 없다.
  if (verdict.decision === DECISION.DENY) {
    ctx.audit.append({ ...baseAudit, tool: args.tool, outcome: "denied", approver: APPROVER.NONE, decisionReason: verdict.reason });
    throw new Error(`거부됨: ${verdict.reason}`);
  }

  // 2) 자동 허용 — 그래도 로깅한다(§5 "still writes a full log entry for every auto-approved action").
  if (verdict.decision === DECISION.ALLOW) {
    if (verdict.approver === APPROVER.APPROVE_ALL) state.autoApprovedCount += 1;
    ctx.audit.append({ ...baseAudit, tool: args.tool, outcome: "auto-approved", approver: verdict.approver, decisionReason: verdict.reason });
    return { ok: true, approver: verdict.approver, reason: verdict.reason, gateLog };
  }

  // 3) 승인 필요.
  const preview = args.preview;
  if (!preview || !Array.isArray(preview.patterns) || preview.patterns.length === 0) {
    // §5: 미리보기 없는 승인은 asking 으로 치지 않는다(내부 오류 = DENY).
    ctx.audit.append({ ...baseAudit, tool: args.tool, outcome: "denied", approver: APPROVER.NONE, decisionReason: "승인 미리보기를 만들지 못함(fail-closed)" });
    throw new Error("거부됨: 승인 미리보기를 만들지 못해 fail-closed 처리함(내부 오류).");
  }

  const attemptKey = `${action}:${target?.resolved ?? ""}`;
  const attempt = state.bumpAttempt(attemptKey);

  // 3a) 감사자 모드이고 감사자가 대신 승인할 수 있는 판정일 때만 (§4)
  if (verdict.canAuditorApprove && state.auditorMode && policy.auditor.enabled) {
    const outcome = await runAuditor({
      client: ctx.client,
      policy,
      parentSessionId: context.sessionID,
      envelope: {
        action,
        target: { requested: target?.requested, resolved: target?.resolved, kind: target?.kind },
        risk: args.classification?.risk ?? RISK.STATIC,
        classification: {
          summary: args.classification?.summary ?? "",
          reasons: args.classification?.reasons ?? [],
          hardSignatures: args.classification?.contentScan?.hard ?? [],
        },
        hardDenied,
        beforeSha256: args.audit?.beforeSha256,
        afterSha256: args.audit?.afterSha256,
        diff: args.audit?.diffText,
        contentExcerpt: args.audit?.contentExcerpt,
      },
      log: ctx.log,
      attempt: { retriesLeft: Math.max(0, policy.auditor.maxRetries - (attempt.count - 1)), previousReasons: attempt.auditorDenials },
    });
    gateLog.push({ stage: "auditor", ...outcome, verdict: outcome.verdict ? { verdict: outcome.verdict.verdict, reasons: outcome.verdict.reasons, parseOk: outcome.verdict.parseOk, injectionSuspected: outcome.verdict.injectionSuspected } : null });
    // §4: 승인/거부 모두 전체 추론을 로그에 남긴다.
    ctx.audit.append({
      ...baseAudit,
      tool: args.tool,
      stage: "auditor",
      outcome: outcome.effectiveApproval ? "auditor-approved" : "auditor-denied",
      approver: outcome.effectiveApproval ? APPROVER.AUDITOR : APPROVER.NONE,
      auditorVerdict: outcome.verdict?.verdict ?? null,
      auditorReasons: outcome.verdict?.reasons ?? [],
      auditorRisks: outcome.verdict?.risks ?? [],
      auditorInjectionSuspected: outcome.verdict?.injectionSuspected ?? false,
      auditorParseOk: outcome.verdict?.parseOk ?? false,
      decisionReason: outcome.reason,
      retriesLeft: Math.max(0, policy.auditor.maxRetries - (attempt.count - 1)),
    });
    if (outcome.effectiveApproval) {
      return { ok: true, approver: APPROVER.AUDITOR, reason: outcome.reason, gateLog };
    }
    state.recordAuditorDenial(attemptKey, outcome.reason);
  }

  // 3b) 인간 직접 승인 (감사자 모드가 꺼졌거나, deny-list 이거나, 감사자가 approve 하지 않은 경우)
  const human = await ctx.gate.requestHumanApproval({
    context,
    permission: verdict.permission ?? PERMISSION.WRITE,
    patterns: preview.patterns,
    metadata: preview.metadata,
    kind: `${action}:${args.classification?.risk ?? RISK.STATIC}`,
    auditContextId: target?.resolved,
  });
  gateLog.push({ stage: "human", ok: human.ok, reason: human.reason, approver: human.approver, bypass: (human as any).bypass });
  ctx.audit.append({
    ...baseAudit,
    tool: args.tool,
    stage: "human",
    outcome: human.ok ? "human-approved" : "denied",
    approver: human.approver ?? APPROVER.NONE,
    decisionReason: human.reason,
    previewPatterns: preview.patterns,
    permissionRequested: verdict.permission,
    requestId: human.requestId,
    timedOut: human.timedOut === true,
    gateBypassDetected: (human as any).bypass === true,
  });
    if (!human.ok) throw new Error(`거부됨: ${human.reason}`);
    // §3 5단계: 읽기/목록을 사람이 승인하면 그 경로가 세션 허용 목록에 들어간다.
    // (이후 같은 경로 접근은 다시 묻지 않는다. 목록 밖 경로는 여전히 다시 묻는다.)
    if ((action === ACTION.READ || action === ACTION.LIST) && target?.resolved && !target?.inScope) {
      const match = matchScope(state.scopePaths, target.resolved);
      if (!match.inScope) state.scopePaths.push(target.resolved);
    }
    return { ok: true, approver: human.approver ?? APPROVER.HUMAN, reason: human.reason, gateLog };
}

/** 툴별 공통: 대상 해석. 허용 루트 밖/순회/심볼릭 링크 이탈은 여기서 DENY 된다. */
async function resolveOrThrow(ctx, context, path, opts: any = {}) {
  const state = ctx.state(context.sessionID, context.agent);
  const r = await ctx.transport.resolveTarget(path, { scopePaths: state.scopePaths, ...opts });
  if (!r.ok) {
    ctx.audit.append({
      sessionID: context.sessionID,
      agent: context.agent,
      tool: opts.tool,
      outcome: "denied",
      approver: APPROVER.NONE,
      requested: r.requested,
      decisionReason: r.reason,
    });
    throw new Error(`경로 거부: ${r.reason}`);
  }
  return r;
}

/** 읽기 결과를 모델에 돌려줄 형태로 만든다(바이너리/인코딩/자르기 처리, §7). */
function renderReadResult(ctx, path, buffer, opts: any = {}) {
  const maxBytes = Math.min(opts.maxBytes ?? ctx.policy.maxReadBytes, ctx.policy.maxReadBytes);
  const binary = looksBinary(buffer);
  const digest = sha256(buffer);
  if (binary) {
    const slice = buffer.subarray(0, Math.min(buffer.length, Math.min(maxBytes, 256 * 1024)));
    return {
      path,
      kind: "binary",
      size: buffer.length,
      sha256: digest,
      note: `바이너리 파일 — base64 로 ${slice.length}B 만 전달함(전체 ${humanBytes(buffer.length)}).`,
      base64: slice.toString("base64"),
      full: buffer.length <= slice.length,
    };
  }
  let text = buffer.toString("utf8");
  let masked = 0;
  if (ctx.policy.redactSecretLookingContentOnRead) {
    const r = maskCredentialLikeValues(text);
    text = r.text;
    masked = r.masked;
  }
  const clipped = truncateBytes(text, maxBytes);
  const notes: string[] = [];
  if (clipped.truncated) notes.push(`내용이 잘렸다: ${humanBytes(clipped.bytes)} 중 ${humanBytes(maxBytes)} 만 전달.`);
  if (masked > 0) notes.push(`자격증명처럼 보이는 값 ${masked}개를 «masked» 로 가렸다(비밀은 모델로 흘리지 않는다).`);
  return { path, kind: "text", size: buffer.length, sha256: digest, text: clipped.text, note: notes.join(" ") || undefined };
}

/** 실행 결과 감사 로그(성공/실패 구분). */
function logOutcome(ctx, context, toolName, entry) {
  ctx.audit.append({ sessionID: context.sessionID, agent: context.agent, tool: toolName, ...entry });
}

/**
 * 툴 반환값 래퍼.
 * opencode 의 ToolResult 계약은 `string | { title?, output, metadata? }` 이다
 * (임의 객체를 그대로 돌려주면 output 이 undefined 가 되어 모델이 아무것도 못 본다 —
 *  실제로 이 플러그인을 쓰려면 반드시 이 래퍼를 거칠 것).
 * 사람이/모델이 읽을 요약을 output 으로, 기계가 쓸 구조체를 metadata.sftp 으로 넣는다.
 */
function finish(input) {
  const lines = Array.isArray(input.lines) ? input.lines.filter((l) => l !== undefined && l !== null && l !== "") : [];
  return {
    title: input.title,
    output: lines.join("\n"),
    metadata: { sftp: input.data ?? null },
  };
}

export function createTools(ctx) {
  // ── sftp_list ────────────────────────────────────────────────────────────
  const sftp_list = tool({
    description:
      "원격(SFTP) 디렉터리 1단계 목록. §2 에 따라 승인 범위 밖이면 먼저 범위 승인을 요구한다. 재귀 탐색은 sftp_propose_scope 를 쓸 것.",
    args: {
      path: tool.schema.string().describe("원격 절대 경로 (chroot 내부 기준, 예: /var/www/html/plugin)"),
    },
    async execute(args, context) {
      const target = await resolveOrThrow(ctx, context, args.path, { tool: "sftp_list" });
      if (target.kind === "absent") throw new Error(`디렉터리가 존재하지 않음: ${target.resolved}`);
      const preview = {
        title: `SFTP 목록 읽기: ${target.resolved}`,
        patterns: ["SFTP 읽기(목록)", `대상: ${target.resolved}`, `종류: ${target.kind}`, `승인 범위 안: ${target.inScope ? "예" : "아니오"}`],
        metadata: { filepath: target.resolved },
        text: "",
      };
      const gate = await authorizeGuarded({ action: ACTION.LIST, context, ctx, target, preview, tool: "sftp_list" });
      const listed = await ctx.transport.listDir(target.resolved);
      if (!listed.ok) {
        logOutcome(ctx, context, "sftp_list", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: listed.reason });
        throw new Error(`목록 실패: ${listed.reason}`);
      }
      ctx.state(context.sessionID).touchedPaths.add(target.resolved);
      logOutcome(ctx, context, "sftp_list", { outcome: "ok", resolved: target.resolved, approver: gate.approver, entryCount: listed.entries.length });
      context.metadata({ title: `SFTP 목록 ${listed.entries.length}개: ${target.resolved}` });
      return finish({
        title: `SFTP 목록 ${listed.entries.length}개: ${target.resolved}`,
        lines: [
          `경로: ${target.resolved} (승인: ${gate.approver})`,
          `항목 ${listed.entries.length}개 — 형식: 타입 크기 이름`,
          ...listed.entries.map((e) => `${e.type === "dir" ? "d" : e.type === "symlink" ? "l" : "-"} ${String(e.size ?? 0).padStart(10)}  ${e.name}`),
        ],
        data: { path: target.resolved, approver: gate.approver, entries: listed.entries },
      });
    },
  });

  // ── sftp_read ────────────────────────────────────────────────────────────
  const sftp_read = tool({
    description:
      "원격 파일 읽기. 바이너리는 base64 로 일부만, 텍스트는 UTF-8 로 돌려준다(비 UTF-8 손상 없음). 자격증명처럼 보이는 값은 자동 마스킹된다.",
    args: {
      path: tool.schema.string().describe("원격 절대 경로"),
      maxBytes: tool.schema.number().optional().describe("요청 최대 바이트(정책 상한을 넘겨도 상한이 우선)"),
    },
    async execute(args, context) {
      const target = await resolveOrThrow(ctx, context, args.path, { mustExist: true, tool: "sftp_read" });
      const preview = {
        title: `SFTP 읽기: ${target.resolved}`,
        patterns: ["SFTP 읽기", `대상: ${target.resolved}`, `종류: ${target.kind}`],
        metadata: { filepath: target.resolved },
        text: "",
      };
      const gate = await authorizeGuarded({ action: ACTION.READ, context, ctx, target, preview, tool: "sftp_read" });
      const readLimit = Math.min(args.maxBytes ?? ctx.policy.maxReadBytes, ctx.policy.maxReadBytes);
      const read = await ctx.transport.readFile(target.resolved, readLimit);
      if (!read.ok) {
        logOutcome(ctx, context, "sftp_read", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: read.reason });
        throw new Error(`읽기 실패: ${read.reason}`);
      }
      const rendered = renderReadResult(ctx, target.resolved, read.buffer, { maxBytes: args.maxBytes });
      logOutcome(ctx, context, "sftp_read", {
        outcome: "ok",
        resolved: target.resolved,
        approver: gate.approver,
        size: rendered.size,
        sha256: rendered.sha256,
        kind: rendered.kind,
      });
      context.metadata({ title: `SFTP 읽기 ${humanBytes(rendered.size)}: ${target.resolved}` });
      if (rendered.kind === "binary") {
        return finish({
          title: `SFTP 읽기(바이너리) ${humanBytes(rendered.size)}: ${target.resolved}`,
          lines: [
            `경로: ${target.resolved} (승인: ${gate.approver})`,
            `종류: 바이너리 / 크기: ${humanBytes(rendered.size)} / sha256: ${rendered.sha256}`,
            `참고: ${rendered.note}`,
            `base64 (${rendered.full ? "전체" : "앞부분"}):`,
            rendered.base64,
          ],
          data: rendered,
        });
      }
      return finish({
        title: `SFTP 읽기 ${humanBytes(rendered.size)}: ${target.resolved}`,
        lines: [
          `경로: ${target.resolved} (승인: ${gate.approver})`,
          `종류: 텍스트 / 크기: ${humanBytes(rendered.size)} / sha256: ${rendered.sha256}`,
          rendered.note ? `참고: ${rendered.note}` : undefined,
          "---- 내용 시작 ----",
          rendered.text ?? "",
          "---- 내용 끝 ----",
        ],
        data: rendered,
      });
    },
  });

  // ── sftp_stat ────────────────────────────────────────────────────────────
  const sftp_stat = tool({
    description: "원격 경로의 속성(크기/모드/타입/심볼릭 링크 여부)과 경로 기반 위험 분류를 반환한다. 내용은 읽지 않는다.",
    args: { path: tool.schema.string().describe("원격 절대 경로") },
    async execute(args, context) {
      const target = await resolveOrThrow(ctx, context, args.path, { tool: "sftp_stat" });
      const classification = classifyTarget({ path: target.resolved });
      const preview = {
        title: `SFTP 조회: ${target.resolved}`,
        patterns: ["SFTP 조회(stat)", `대상: ${target.resolved}`, `분류: ${classification.summary}`],
        metadata: { filepath: target.resolved },
        text: "",
      };
      const gate = await authorizeGuarded({ action: ACTION.READ, context, ctx, target, classification, preview, tool: "sftp_stat" });
      const st = await ctx.transport.stat(target.resolved);
      if (!st.ok) {
        logOutcome(ctx, context, "sftp_stat", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: st.reason });
        throw new Error(`속성 조회 실패: ${st.reason}`);
      }
      logOutcome(ctx, context, "sftp_stat", { outcome: "ok", resolved: target.resolved, approver: gate.approver, size: st.attrs.size, risk: classification.risk });
      return finish({
        title: `SFTP 조회: ${target.resolved}`,
        lines: [
          `경로: ${target.resolved} (승인: ${gate.approver})`,
          `존재: ${target.kind !== "absent"} / 종류: ${target.kind}`,
          `크기: ${humanBytes(st.attrs.size ?? 0)} / 권한: ${st.attrs.mode} / uid:${st.attrs.owner} gid:${st.attrs.group}`,
          `마지막 수정: ${new Date(st.attrs.modifyTime ?? 0).toISOString()}`,
          `위험 분류: ${classification.risk} — ${classification.reasons.join(" | ") || "정적 파일"}`,
        ],
        data: { path: target.resolved, approver: gate.approver, attrs: st.attrs, risk: classification.risk, reasons: classification.reasons, exists: target.kind !== "absent" },
      });
    },
  });

  // ── sftp_write_new ───────────────────────────────────────────────────────
  const sftp_write_new = tool({
    description:
      "새 파일 작성(원자적 no-clobber: 이미 있으면 실패). 고위험/웹서버 설정 파일은 항상 사람의 승인이 필요하다. 기존 파일 수정은 sftp_edit_existing 을 쓸 것.",
    args: {
      path: tool.schema.string().describe("원격 절대 경로 (아직 없어야 함)"),
      content: tool.schema.string().optional().describe("UTF-8 텍스트 내용 (contentBase64 와 동시에 지정 불가)"),
      contentBase64: tool.schema.string().optional().describe("바이너리 내용 base64 (content 와 동시에 지정 불가)"),
      mode: tool.schema.number().optional().describe("파일 권한(8진수 값으로 주면 됨, 예: 420 = 0644)"),
    },
    async execute(args, context) {
      const buffer = decodeContentArgs(args, ctx);
      if (buffer.length > ctx.policy.maxWriteBytes) {
        throw new Error(`크기 초과: ${humanBytes(buffer.length)} > 정책 상한 ${humanBytes(ctx.policy.maxWriteBytes)}`);
      }
      const target = await resolveOrThrow(ctx, context, args.path, { tool: "sftp_write_new" });
      if (target.kind !== "absent") {
        throw new Error(`이미 존재하는 경로라 새 파일로 만들 수 없음: ${target.resolved} — 수정이면 sftp_edit_existing 을 쓸 것.`);
      }
      const classification = classifyTarget({ path: target.resolved, content: buffer, maxScanBytes: ctx.policy.maxScanBytes });
      const afterSha = sha256(buffer);
      const diff = buildDiff(Buffer.alloc(0), buffer);
      const mode = normalizeModeArg(args.mode, ctx.policy.defaultFileMode);
      const preview = buildWritePreview({ target, classification, diff, afterSha, action: ACTION.WRITE_NEW });
      const gate = await authorizeGuarded({
        action: ACTION.WRITE_NEW,
        context,
        ctx,
        target,
        classification,
        preview,
        tool: "sftp_write_new",
        audit: { afterSha256: afterSha, size: buffer.length, diffSummary: diffSummary(diff), mode },
      });
      const result = await ctx.transport.withPathLock(`w:${target.resolved}`, () =>
        ctx.transport.writeNewFile(target.resolved, buffer, mode),
      );
      if (!result.ok) {
        logOutcome(ctx, context, "sftp_write_new", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: result.reason, stage: result.stage });
        throw new Error(`생성 실패: ${result.reason}`);
      }
      ctx.state(context.sessionID).touchedPaths.add(target.resolved);
      logOutcome(ctx, context, "sftp_write_new", {
        outcome: "ok",
        resolved: target.resolved,
        approver: gate.approver,
        afterSha256: result.sha256,
        size: result.size,
        mode,
        diffSummary: diffSummary(diff),
      });
      context.metadata({ title: `SFTP 생성 완료: ${target.resolved}` });
      return finish({
        title: `SFTP 생성 완료: ${target.resolved}`,
        lines: [
          `생성됨: ${target.resolved} (승인: ${gate.approver})`,
          `크기: ${humanBytes(result.size)} / sha256: ${result.sha256} / 무결성검증: 통과`,
          `권한: ${result.mode ?? mode}`,
        ],
        data: { path: target.resolved, created: true, size: result.size, sha256: result.sha256, approver: gate.approver, verified: true, mode: result.mode ?? mode },
      });
    },
  });

  // ── sftp_edit_existing ───────────────────────────────────────────────────
  const sftp_edit_existing = tool({
    description:
      "기존 원격 파일 수정. content 로 전체 교체하거나 edits[{find,replace,all}] 로 최소 교체한다(기본: find 는 정확히 1곳이어야 함). 낙관적 동시성 검사(§7)를 한다.",
    args: {
      path: tool.schema.string().describe("원측 절대 경로 (존재해야 함)"),
      content: tool.schema.string().optional().describe("전체 새 내용 UTF-8"),
      contentBase64: tool.schema.string().optional().describe("전체 새 내용 base64(바이너리)"),
      edits: tool.schema
        .array(
          tool.schema.object({
            find: tool.schema.string(),
            replace: tool.schema.string(),
            all: tool.schema.boolean().optional(),
          }),
        )
        .optional()
        .describe("순차 적용할 정확한 문자열 교체 목록 (content 와 동시 사용 불가)"),
      expectedSha256: tool.schema.string().optional().describe("이전 읽기에서 얻은 해시. 다르면 덮어쓰지 않고 실패(§7 동시 세션)"),
      mode: tool.schema.number().optional().describe("권한 변경을 함께 할 때의 모드"),
    },
    async execute(args, context) {
      const hasFull = args.content !== undefined || args.contentBase64 !== undefined;
      const hasEdits = Array.isArray(args.edits) && args.edits.length > 0;
      if (hasFull === hasEdits) throw new Error("content/contentBase64 와 edits 중 정확히 하나만 지정할 것.");
      const target = await resolveOrThrow(ctx, context, args.path, { mustExist: true, tool: "sftp_edit_existing" });
      if (target.kind === "directory") throw new Error(`디렉터리는 수정할 수 없음: ${target.resolved}`);

      const before = await ctx.transport.readFile(target.resolved, ctx.policy.maxWriteBytes);
      if (!before.ok) throw new Error(`기존 파일을 읽지 못해 수정할 수 없음: ${before.reason}`);
      if (looksBinary(before.buffer) && hasEdits) {
        throw new Error("바이너리 파일에는 문자열 교체를 쓸 수 없음 — contentBase64 로 전체를 제공할 것.");
      }
      if (args.expectedSha256 && args.expectedSha256 !== before.sha256) {
        throw new Error(
          `expectedSha256 불일치: 기대 ${args.expectedSha256.slice(0, 12)}… vs 현재 ${String(before.sha256).slice(0, 12)}… — ` +
            `다른 세션이 이미 변경함. 다시 읽고 다시 판단할 것(덮어쓰지 않음).`,
        );
      }

      let next;
      if (hasFull) {
        next = decodeContentArgs(args, ctx);
      } else {
        const applied = applyExactReplaces(before.buffer.toString("utf8"), args.edits);
        if (!applied.ok) throw new Error(`교체 실패: ${applied.reason}`);
        next = Buffer.from(applied.content, "utf8");
      }
      if (next.length > ctx.policy.maxWriteBytes) {
        throw new Error(`크기 초과: ${humanBytes(next.length)} > 정책 상한 ${humanBytes(ctx.policy.maxWriteBytes)}`);
      }
      if (sha256(next) === before.sha256) {
        // 실질 변경이 없으면 아무것도 하지 않는다(승인 프롬프트 낭비 + 불필요한 쓰기 방지).
        return finish({
          title: `SFTP 수정 없음: ${target.resolved}`,
          lines: [`경로: ${target.resolved}`, "새 내용이 기존 내용과 동일 — 쓰지 않았다(승인 요청도 하지 않음)."],
          data: { path: target.resolved, changed: false, reason: "새 내용이 기존 내용과 동일", approver: APPROVER.NONE },
        });
      }

      const classification = classifyTarget({ path: target.resolved, content: next, existingContent: before.buffer, maxScanBytes: ctx.policy.maxScanBytes });
      const afterSha = sha256(next);
      const diff = buildDiff(before.buffer, next);
      const mode = args.mode !== undefined ? normalizeModeArg(args.mode, undefined) : undefined;
      const preview = buildWritePreview({ target, classification, diff, beforeSha: before.sha256, afterSha, action: ACTION.WRITE_EDIT });
      const gate = await authorizeGuarded({
        action: ACTION.WRITE_EDIT,
        context,
        ctx,
        target,
        classification,
        preview,
        tool: "sftp_edit_existing",
        audit: {
          beforeSha256: before.sha256,
          afterSha256: afterSha,
          size: next.length,
          diffSummary: diffSummary(diff),
          diffText: diff.binary ? undefined : truncateBytes(diff.text, 20_000).text,
        },
      });
      const result = await ctx.transport.withPathLock(`w:${target.resolved}`, () =>
        ctx.transport.overwriteFile(target.resolved, next, mode ?? preserveMode(target.attrs), { expectedSha256: before.sha256, backup: before.buffer }),
      );
      if (!result.ok) {
        logOutcome(ctx, context, "sftp_edit_existing", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: result.reason, stage: result.stage });
        throw new Error(`수정 실패: ${result.reason}${result.rolledBack ? " (원래 내용으로 되돌림)" : ""}`);
      }
      ctx.state(context.sessionID).touchedPaths.add(target.resolved);
      logOutcome(ctx, context, "sftp_edit_existing", {
        outcome: "ok",
        resolved: target.resolved,
        approver: gate.approver,
        beforeSha256: before.sha256,
        afterSha256: result.sha256,
        diffSummary: diffSummary(diff),
        rolledBack: result.rolledBack ?? false,
      });
      context.metadata({ title: `SFTP 수정 완료: ${target.resolved} (${diffSummary(diff)})` });
      return finish({
        title: `SFTP 수정 완료: ${target.resolved} (${diffSummary(diff)})`,
        lines: [
          `수정됨: ${target.resolved} (승인: ${gate.approver})`,
          `변경: ${diffSummary(diff)}`,
          `이전 sha256: ${before.sha256}`,
          `이후 sha256: ${result.sha256} / 무결성검증: 통과`,
        ],
        data: {
          path: target.resolved,
          changed: true,
          size: result.size,
          beforeSha256: before.sha256,
          afterSha256: result.sha256,
          diffSummary: diffSummary(diff),
          approver: gate.approver,
          verified: true,
        },
      });
    },
  });

  // ── sftp_delete ──────────────────────────────────────────────────────────
  const sftp_delete = tool({
    description: "원격 파일 1개 삭제. 되돌릴 수 없으므로 항상 파일별 사람 승인이 필요하다(범위/approve-all/감사자로 예외 없음). 디렉터리는 지우지 않는다.",
    args: { path: tool.schema.string().describe("삭제할 원격 파일 절대 경로") },
    async execute(args, context) {
      const target = await resolveOrThrow(ctx, context, args.path, { mustExist: true, tool: "sftp_delete" });
      if (target.kind === "directory") {
        throw new Error(`디렉터리는 이 도구로 지우지 않는다(빈 확인/되돌림 불가): ${target.resolved} — 사람이 직접 처리할 것.`);
      }
      const st = await ctx.transport.stat(target.resolved);
      const read = st.ok && (st.attrs.size ?? 0) <= 256 * 1024 ? await ctx.transport.readFile(target.resolved, 256 * 1024) : { ok: false };
      const head = read.ok && !looksBinary(read.buffer) ? read.buffer.toString("utf8").split("\n").slice(0, 20).join("\n") : undefined;
      const classification = classifyTarget({ path: target.resolved, existingContent: read.ok ? read.buffer : undefined, maxScanBytes: ctx.policy.maxScanBytes });
      const preview = buildDeletePreview({ target, stat: st.ok ? st.attrs : null, sha256: read.ok ? read.sha256 : undefined, head });
      const gate = await authorizeGuarded({
        action: ACTION.DELETE,
        context,
        ctx,
        target,
        classification,
        preview,
        tool: "sftp_delete",
        audit: { size: st.ok ? st.attrs.size : undefined, beforeSha256: read.ok ? read.sha256 : undefined },
      });
      const result = await ctx.transport.withPathLock(`w:${target.resolved}`, () => ctx.transport.deleteFile(target.resolved));
      if (!result.ok) {
        logOutcome(ctx, context, "sftp_delete", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: result.reason, stage: result.stage });
        throw new Error(`삭제 실패: ${result.reason}`);
      }
      logOutcome(ctx, context, "sftp_delete", { outcome: "ok", resolved: target.resolved, approver: gate.approver, beforeSha256: read.ok ? read.sha256 : undefined, size: st.ok ? st.attrs.size : undefined });
      context.metadata({ title: `SFTP 삭제 완료: ${target.resolved}` });
      return finish({
        title: `SFTP 삭제 완료: ${target.resolved}`,
        lines: [`삭제됨: ${target.resolved} (승인: ${gate.approver})`, "되돌릴 수 없음."],
        data: { path: target.resolved, deleted: true, approver: gate.approver },
      });
    },
  });

  // ── sftp_move ────────────────────────────────────────────────────────────
  const sftp_move = tool({
    description: "원격 파일 이동/이름변경. 항상 파일별 사람 승인(오버라이드 없음). 대상이 있으면 overwrite:true 가 필요하다(서버가 원자적 덮어쓰기를 지원하지 않으면 실패하고 조용히 지우지 않는다).",
    args: {
      from: tool.schema.string().describe("출발 절대 경로"),
      to: tool.schema.string().describe("도착 절대 경로"),
      overwrite: tool.schema.boolean().optional().describe("도착 파일이 있어도 덮어쓸지(기본 false)"),
    },
    async execute(args, context) {
      const from = await resolveOrThrow(ctx, context, args.from, { mustExist: true, tool: "sftp_move" });
      if (from.kind === "directory") throw new Error(`디렉터리 이동은 지원하지 않음: ${from.resolved}`);
      const to = await resolveOrThrow(ctx, context, args.to, { tool: "sftp_move" });
      if (to.resolved === from.resolved) throw new Error("출발과 도착이 동일함.");
      const st = await ctx.transport.stat(from.resolved);
      const read = st.ok && (st.attrs.size ?? 0) <= 256 * 1024 ? await ctx.transport.readFile(from.resolved, 256 * 1024) : { ok: false };
      const classification = classifyTarget({ path: from.resolved, existingContent: read.ok ? read.buffer : undefined, maxScanBytes: ctx.policy.maxScanBytes });
      const destClassification = classifyTarget({ path: to.resolved });
      const preview = buildMovePreview({ from: from.resolved, to: to.resolved, stat: st.ok ? st.attrs : null, sha256: read.ok ? read.sha256 : undefined, overwrite: args.overwrite === true });
      const gate = await authorizeGuarded({
        action: ACTION.MOVE,
        context,
        ctx,
        target: { ...from, resolved: from.resolved, requested: from.requested, inScope: from.inScope && to.inScope },
        classification,
        preview,
        tool: "sftp_move",
        audit: { destination: to.resolved, size: st.ok ? st.attrs.size : undefined, beforeSha256: read.ok ? read.sha256 : undefined, destRisk: destClassification.risk },
      });
      const result = await ctx.transport.withPathLock(`w:${from.resolved}`, () => ctx.transport.withPathLock(`w:${to.resolved}`, () => ctx.transport.move(from.resolved, to.resolved, args.overwrite === true)));
      if (!result.ok) {
        logOutcome(ctx, context, "sftp_move", { outcome: "failed", resolved: from.resolved, approver: gate.approver, error: result.reason, stage: result.stage, destination: to.resolved });
        throw new Error(`이동 실패: ${result.reason}`);
      }
      logOutcome(ctx, context, "sftp_move", { outcome: "ok", resolved: from.resolved, approver: gate.approver, destination: to.resolved, beforeSha256: read.ok ? read.sha256 : undefined });
      context.metadata({ title: `SFTP 이동 완료: ${from.resolved} → ${to.resolved}` });
      return finish({
        title: `SFTP 이동 완료: ${from.resolved} → ${to.resolved}`,
        lines: [`이동됨 (승인: ${gate.approver})`, `출발: ${from.resolved}`, `도착: ${to.resolved}`],
        data: { from: from.resolved, to: to.resolved, moved: true, approver: gate.approver },
      });
    },
  });

  // ── sftp_mkdir ───────────────────────────────────────────────────────────
  const sftp_mkdir = tool({
    description: "원격 디렉터리 생성. 승인 범위 안이면 자동 허용(로그 기록), 밖이면 확인 후 생성.",
    args: {
      path: tool.schema.string().describe("생성할 원격 디렉터리 절대 경로"),
      recursive: tool.schema.boolean().optional().describe("상위 디렉터리도 함께 생성(기본 false)"),
      mode: tool.schema.number().optional().describe("디렉터리 권한(8진수 값)"),
    },
    async execute(args, context) {
      const target = await resolveOrThrow(ctx, context, args.path, { tool: "sftp_mkdir" });
      if (target.kind === "directory") {
        return finish({
          title: `SFTP 디렉터리 이미 존재: ${target.resolved}`,
          lines: [`경로: ${target.resolved}`, "이미 존재하는 디렉터리 — 아무것도 하지 않았다."],
          data: { path: target.resolved, created: false, reason: "이미 존재하는 디렉터리", approver: APPROVER.NONE },
        });
      }
      if (target.kind !== "absent") throw new Error(`대상이 이미 존재함(디렉터리가 아님): ${target.resolved}`);
      const mode = normalizeModeArg(args.mode, 0o755);
      const preview = {
        title: `SFTP 디렉터리 생성: ${target.resolved}`,
        patterns: ["SFTP mkdir", `생성 경로: ${target.resolved}`, `재귀: ${args.recursive === true}`, `권한: 0${(mode & 0o7777).toString(8)}`, `승인 범위 안: ${target.inScope ? "예" : "아니오"}`],
        metadata: { filepath: target.resolved },
        text: "",
      };
      const gate = await authorizeGuarded({ action: ACTION.MKDIR, context, ctx, target, preview, tool: "sftp_mkdir" });
      const result = await ctx.transport.withPathLock(`w:${target.resolved}`, () => ctx.transport.mkdir(target.resolved, args.recursive === true, mode));
      if (!result.ok) {
        logOutcome(ctx, context, "sftp_mkdir", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: result.reason });
        throw new Error(`디렉터리 생성 실패: ${result.reason}`);
      }
      logOutcome(ctx, context, "sftp_mkdir", { outcome: "ok", resolved: target.resolved, approver: gate.approver, mode });
      context.metadata({ title: `SFTP 디렉터리 생성 완료: ${target.resolved}` });
      return finish({
        title: `SFTP 디렉터리 생성 완료: ${target.resolved}`,
        lines: [`생성됨: ${target.resolved} (승인: ${gate.approver})`, `권한: ${result.mode ?? mode}`],
        data: { path: target.resolved, created: true, approver: gate.approver, mode: result.mode ?? mode },
      });
    },
  });

  // ── sftp_chmod ───────────────────────────────────────────────────────────
  const sftp_chmod = tool({
    description: "원격 파일/디렉터리 권한 변경. 실행 비트를 추가하면 고위험 파일 생성과 동등 취급되어 항상 사람의 승인이 필요하다.",
    args: {
      path: tool.schema.string().describe("대상 원격 절대 경로"),
      mode: tool.schema.number().describe("새 권한(8진수 값으로 주면 됨. 예: 493 = 0755)"),
    },
    async execute(args, context) {
      const target = await resolveOrThrow(ctx, context, args.path, { mustExist: true, tool: "sftp_chmod" });
      const newMode = normalizeModeArg(args.mode, null);
      if (newMode === null) throw new Error("mode 값이 올바르지 않음(0 이상 정수).");
      const before = await ctx.transport.stat(target.resolved);
      const beforeMode = before.ok ? normalizeModeValue(before.attrs.mode) : null;
      const addsExecuteBit = (newMode & 0o111) !== 0 && (beforeMode === null || (beforeMode & 0o111) === 0);
      const classification = classifyTarget({ path: target.resolved, flags: { addsExecuteBit } });
      const preview = buildChmodPreview({ target, beforeMode, afterMode: newMode, addsExecuteBit });
      const gate = await authorizeGuarded({
        action: ACTION.CHMOD,
        context,
        ctx,
        target,
        classification,
        preview,
        addsExecuteBit,
        tool: "sftp_chmod",
      });
      const result = await ctx.transport.withPathLock(`w:${target.resolved}`, () => ctx.transport.chmod(target.resolved, newMode));
      if (!result.ok) {
        logOutcome(ctx, context, "sftp_chmod", { outcome: "failed", resolved: target.resolved, approver: gate.approver, error: result.reason });
        throw new Error(`권한 변경 실패: ${result.reason}`);
      }
      logOutcome(ctx, context, "sftp_chmod", {
        outcome: "ok",
        resolved: target.resolved,
        approver: gate.approver,
        beforeMode: result.beforeMode,
        afterMode: result.afterMode,
        addsExecuteBit,
      });
      context.metadata({ title: `SFTP chmod 완료: ${target.resolved}` });
      return finish({
        title: `SFTP chmod 완료: ${target.resolved}`,
        lines: [
          `권한 변경됨 (승인: ${gate.approver})`,
          `대상: ${target.resolved}`,
          `${result.beforeMode} → ${result.afterMode}`,
          `실행 비트 추가: ${addsExecuteBit ? "예 (고위-risk 취급됨)" : "아니오"}`,
        ],
        data: { path: target.resolved, beforeMode: result.beforeMode, afterMode: result.afterMode, addsExecuteBit, approver: gate.approver },
      });
    },
  });

  // ── sftp_propose_scope ───────────────────────────────────────────────────
  const sftp_propose_scope = tool({
    description:
      "읽기 전용으로 폴더 구조를 훑어 humans 가 승인할 구체적 범위 목록을 만든다(§3 2단계). 심볼릭 링크/상위 디렉터리로 확장되지 않는다. 처음 한 번은 사람의 확인이 필요하다.",
    args: {
      basePath: tool.schema.string().describe("사람이 알려 준 기준 경로 (허용 루트 안이어야 함)"),
      maxDepth: tool.schema.number().optional().describe("탐색 깊이(정책 상한 이하)"),
    },
    async execute(args, context) {
      const state = ctx.state(context.sessionID, context.agent);
      // 사람이 준 base path 라는 전제는 모델의 주장이다. 설정으로 고정해 둔 값이 있으면 그것으로 검증한다.
      if (ctx.policy.initialBasePath) {
        const g = guardPath({ path: args.basePath, allowedRoots: ctx.policy.allowedRoots });
        if (!g.ok) throw new Error(`기준 경로 거부: ${g.reason}`);
        const under = g.path === ctx.policy.initialBasePath || g.path.startsWith(`${ctx.policy.initialBasePath}/`);
        if (!under) {
          throw new Error(
            `기준 경로가 정책에 고정된 값 밖이다: ${g.path} (허용: ${ctx.policy.initialBasePath}) — ` +
              `사람의 지시 문구를 그대로 전달할 것.`,
          );
        }
      }
      const base = await resolveOrThrow(ctx, context, args.basePath, { mustExist: true, tool: "sftp_propose_scope" });
      if (base.kind !== "directory") throw new Error(`기준 경로가 디렉터리가 아님: ${base.resolved}`);

      // 첫 탐색은 사람이 한 번 확인해야 한다(모델이 임의 경로를 탐색하지 못하게).
      if (!state.discoveryRoot) {
        const preview = {
          title: `SFTP 탐색 허용 요청: ${base.resolved}`,
          patterns: ["SFTP 읽기 전용 탐색 시작", `기준 경로: ${base.resolved}`, "내용을 바꾸지 않는다(읽기 전용)", "이후 이 폴더 안의 읽기는 자동 허용된다"],
          metadata: { filepath: base.resolved },
          text: "",
        };
        const gate = await authorizeGuarded({
          action: ACTION.SCOPE,
          context,
          ctx,
          target: { ...base, inScope: false },
          preview,
          tool: "sftp_propose_scope",
        });
        state.discoveryRoot = base.resolved;
        logOutcome(ctx, context, "sftp_propose_scope", { outcome: "ok", resolved: base.resolved, approver: gate.approver, stage: "discovery-root" });
      }

      const walk = await walkTree(ctx, base.resolved, Math.min(args.maxDepth ?? ctx.policy.maxWalkDepth, ctx.policy.maxWalkDepth), ctx.policy.maxWalkEntries);
      const suggested = walk.directories.slice(0, 12).concat([base.resolved]);
      const preview = buildScopePreview({ paths: suggested.map((p) => ({ path: p, kind: "directory", note: "범위 후보" })), basePath: base.resolved, entries: { total: walk.total, depth: walk.depth, truncated: walk.truncated, sample: walk.sample } });
      logOutcome(ctx, context, "sftp_propose_scope", { outcome: "ok", resolved: base.resolved, entries: walk.total, truncated: walk.truncated, suggestedCount: suggested.length });
      context.metadata({ title: `SFTP 탐색 완료: ${walk.total}개 항목 (기준 ${base.resolved})` });
      return finish({
        title: `SFTP 탐색 완료: ${walk.total}개 항목 (기준 ${base.resolved})`,
        lines: [
          `기준 경로: ${base.resolved}`,
          `탐색 루트(읽기 자동 허용): ${state.discoveryRoot}`,
          `항목 ${walk.total}개, 최대 깊이 ${ctx.policy.maxWalkDepth}, 절단: ${walk.truncated ? "예(상한 도달)" : "아니오"}`,
          "---- 구조 ----",
          ...walk.sample,
          "---- 범위 후보 ----",
          ...suggested.map((p) => `  • ${p}`),
          `다음 단계: ${"구체적 범위를 정했다면 sftp_request_scope_approval 에 경로 목록을 그대로 넘길 것(§3 3단계)."}`,
        ],
        data: {
          basePath: base.resolved,
          discoveryRoot: state.discoveryRoot,
          totalEntries: walk.total,
          truncated: walk.truncated,
          tree: walk.sample,
          suggestedScope: suggested,
        },
      });
    },
  });

  // ── sftp_request_scope_approval ──────────────────────────────────────────
  const sftp_request_scope_approval = tool({
    description:
      "구체적 경로 목록에 대한 작업 범위 승인을 사람에게 요청한다(§3 3단계). 승인된 목록은 이 세션에서만 유효하고, 목록 밖 경로는 다시 승인을 물어본다.",
    args: {
      paths: tool.schema.array(tool.schema.string()).describe("자동 허용을 받을 경로 목록(파일 또는 폴더, 최소 1개)"),
      note: tool.schema.string().optional().describe("사람에게 보여줄 한 줄 목적 설명"),
    },
    async execute(args, context) {
      const state = ctx.state(context.sessionID, context.agent);
      if (!Array.isArray(args.paths) || args.paths.length === 0) throw new Error("paths 가 비어 있음.");
      if (args.paths.length > 50) throw new Error(`한 번에 50개를 초과하는 범위 승인은 요청하지 않는다(요청: ${args.paths.length}).`);
      const resolved: Array<{ path: string; kind: string; note?: string; classification?: any; requested?: string; inScope?: boolean }> = [];
      for (const p of args.paths) {
        const t = await resolveOrThrow(ctx, context, p, { tool: "sftp_request_scope_approval" });
        const classification = classifyTarget({ path: t.resolved });
        const sensitive = hasSensitivePathToken(t.resolved);
        const notes: string[] = [];
        if (classification.risk !== RISK.STATIC) notes.push(`고위험(${classification.risk}) — 읽기는 가능하지만 쓰기는 별도 승인`);
        if (sensitive.length) notes.push(`민감 경로 토큰: ${sensitive.join(", ")} — 쓰기는 deny-list 대상이 될 수 있음`);
        resolved.push({
          path: t.resolved,
          kind: t.kind,
          requested: t.requested,
          inScope: t.inScope,
          classification,
          note: notes.length ? notes.join(" / ") : undefined,
        });
      }
      const preview = buildScopePreview({
        paths: resolved.map((r) => ({ path: r.path, kind: r.kind, note: r.note })),
        basePath: state.discoveryRoot ?? resolved[0].path,
        entries: null,
      });
      if (args.note) preview.patterns = [`목적: ${scrubText(args.note).slice(0, 200)}`, ...preview.patterns.slice(1)];
      const gate = await authorizeGuarded({
        action: ACTION.SCOPE,
        context,
        ctx,
        target: { requested: resolved.map((r) => r.requested).join(","), resolved: resolved.map((r) => r.path).join(","), kind: "scope", inScope: false, root: ctx.policy.allowedRoots[0] },
        preview,
        tool: "sftp_request_scope_approval",
        audit: { paths: resolved.map((r) => r.path), kinds: resolved.map((r) => r.kind) },
      });
      const added: string[] = [];
      for (const r of resolved) {
        if (!state.scopePaths.includes(r.path)) {
          state.scopePaths.push(r.path);
          added.push(r.path);
        }
      }
      logOutcome(ctx, context, "sftp_request_scope_approval", { outcome: "ok", resolved: added.join(","), approver: gate.approver, requestedCount: resolved.length, addedCount: added.length });
      context.metadata({ title: `SFTP 범위 승인됨: ${added.length}개 경로` });
      return finish({
        title: `SFTP 범위 승인됨: ${added.length}개 경로`,
        lines: [
          `승인된 경로 ${added.length}개 (승인: ${gate.approver})`,
          ...added.map((p) => `  • ${p}`),
          `현재 세션 허용 목록(${state.scopePaths.length}개): ${state.scopePaths.join(", ")}`,
          "주의: 이 목록은 이 세션에서만 유효하다(디스크에 저장되지 않음). 목록 밖 경로는 다시 승인을 물어본다.",
        ],
        data: { approved: added, scopePaths: [...state.scopePaths], approver: gate.approver, sessionOnly: true },
      });
    },
  });

  // ── sftp_set_mode ────────────────────────────────────────────────────────
  const sftp_set_mode = tool({
    description:
      "이 세션의 SFTP 작업 모드 변경/조회. 격하 방향(approve-all 끄기, 상한 줄이기, 감사자 모드 켜기)은 모델이 직접 할 수 있다. " +
      "approve-all 을 켜는 것은 기본적으로 거부된다(§0: 모델이 스스로 권한을 넓힐 수 없어야 한다) — 정책에서 allowModelApproveAll:true 인 경우에만 게이트를 통해 가능하다.",
    args: {
      approveAll: tool.schema.boolean().optional().describe("static 파일 자동 허용 토글(기본: 모델이 켤 수 없음)"),
      auditorMode: tool.schema.boolean().optional().describe("감사자 모드 ON/OFF (ON 은 권한을 낮추므로 모델이 켤 수 있음)"),
      batchCap: tool.schema.number().optional().describe("approve-all 자동 허용 상한을 이 값으로 낮추기(1~정책 상한)"),
    },
    async execute(args, context) {
      const state = ctx.state(context.sessionID, context.agent);
      const changes: string[] = [];
      // 1) 항상 허용 해제는 즉시 허용(권한 감소).
      if (args.approveAll === false && state.approveAll) {
        state.approveAll = false;
        state.autoApprovedCount = 0;
        changes.push("approve-all OFF");
        logOutcome(ctx, context, "sftp_set_mode", { outcome: "ok", approver: APPROVER.SCOPE_AUTO, decisionReason: "approve-all 해제(권한 감소)" });
      }
      // 2) 상한 감소도 즉시 허용.
      if (args.batchCap !== undefined) {
        const cap = Math.max(1, Math.min(Math.floor(args.batchCap), ctx.policy.approveAllBatchCap));
        if (cap < (state.batchCap ?? ctx.policy.approveAllBatchCap)) {
          state.batchCap = cap;
          changes.push(`approve-all 상한 ${cap}으로 낮춤`);
        }
      }
      // 3) 감사자 모드 ON — 권한을 낮추는 방향이지만, 사람이 인지했는지 확인해야 하므로 로그에 남긴다.
      if (args.auditorMode !== undefined && args.auditorMode !== state.auditorMode) {
        state.auditorMode = args.auditorMode;
        changes.push(`감사자 모드 ${args.auditorMode ? "ON" : "OFF"}`);
      }
      // 4) approve-all ON — 하드닝: 정책이 허용할 때만, 그리고 반드시 게이트를 통과해야 한다.
      if (args.approveAll === true) {
        if (!state.approveAll) {
          if (!ctx.policy.allowModelApproveAll) {
            const err =
              `approve-all 켜기는 모델이 직접 할 수 없습니다(§0 — 모델이 스스로 권한을 넓히면 승인의 의미가 없어진다). ` +
              `사람이 직접 하려면: 정책 파일의 allowModelApproveAll 를 true 로 두거나, 이 세션에서 sftp_set_mode(approveAll=true) 를 직접 실행할 것.`;
            logOutcome(ctx, context, "sftp_set_mode", { outcome: "denied", approver: APPROVER.NONE, decisionReason: err });
            throw new Error(err);
          }
          const preview = buildModePreview({
            changes: ["approve-all ON — 범위 안의 static 파일을 자동 허용(로그는 남김)"],
            current: `approve-all=${state.approveAll}, 상한=${state.batchCap ?? ctx.policy.approveAllBatchCap}`,
          });
          const gate = await authorizeGuarded({
            action: ACTION.MODE,
            context,
            ctx,
            target: { requested: "(세션 전역)", resolved: "(세션 전역)", kind: "mode", inScope: false, root: null },
            preview,
            tool: "sftp_set_mode",
          });
          state.approveAll = true;
          state.autoApprovedCount = 0;
          state.batchCap = ctx.policy.approveAllBatchCap;
          changes.push("approve-all ON");
          logOutcome(ctx, context, "sftp_set_mode", { outcome: "ok", approver: gate.approver, decisionReason: "approve-all ON" });
        }
      }
      return finish({
        title: `SFTP 모드: ${changes.length ? changes.join(", ") : "변경 없음"}`,
        lines: [
          `세션 ID: ${state.sessionId} / 에이전트: ${state.agent || "-"}`,
          `탐색 루트: ${state.discoveryRoot ?? "(없음)"}`,
          `허용 목록(${state.scopePaths.length}개): ${state.scopePaths.join(", ") || "(없음)"}`,
          `approve-all: ${state.approveAll} (자동 허용 사용 ${state.autoApprovedCount}/${state.batchCap ?? ctx.policy.approveAllBatchCap})`,
          `감사자 모드: ${state.auditorMode} (정책 auditor.enabled=${policyEnabled(ctx)})`,
          `이번 호출로 바뀐 것: ${changes.length ? changes.join(", ") : "없음"}`,
          "주의: 세션 한정(디스크에 저장되지 않음). 새 세션이면 초기화된다.",
        ],
        data: { ...state.describe(), batchCap: state.batchCap ?? ctx.policy.approveAllBatchCap, applied: changes },
      });
    },
  });

  // ── sftp_doctor ──────────────────────────────────────────────────────────
  const sftp_doctor = tool({
    description:
      "진단. 127.0.0.1:22(컨테이너→호스트 루프백) SFTP 도달 가능성, chroot 루트, 두 bind mount 의 쓰기 가능성, " +
      "승인 게이트(permission 규칙) 상태를 확인한다. 기본은 읽기 전용이며, probeWrite:true 면 임시 파일로 쓰기/정리를 확인한다(사람 승인 필요).",
    args: {
      probeWrite: tool.schema.boolean().optional().describe("각 허용 루트에 임시 파일을 만들어 쓰기 권한을 실제로 확인"),
      probeGate: tool.schema.boolean().optional().describe("승인 게이트가 실제로 살아 있는지(사람에게 테스트 승인을 띄움)"),
    },
    async execute(args, context) {
      const report: Record<string, any> = { at: new Date().toISOString(), secretsConfigured: Boolean(ctx.configSummary) };
      report.config = ctx.configSummary;
      const conn = await ctx.transport.ensureConnected();
      report.connection = { ok: conn.ok, error: conn.ok ? undefined : conn.error, status: ctx.transport.status() };
      if (!conn.ok) {
        report.diagnosis =
          "§0.1: 이 플러그인은 컨테이너→호스트 루프백(127.0.0.1 또는 host.docker.internal, 포트 22)으로만 동작한다. " +
          "공개 도메인/DDNS/포트 포워딩 경로는 필요도 의존도도 아니다. 확인 순서: (1) 호스트 sshd listening 여부, " +
          "(2) Docker 네트워크가 이 포트로 나가는지(네트워크 정책 예외 필요), (3) sshd_config 의 Match User <sftp-user> 블록에 ChrootDirectory/ForceCommand 가 있는가(★ 포트 조건이 있으면 안 된다).";
        logOutcome(ctx, context, "sftp_doctor", { outcome: "failed", error: conn.error });
        context.metadata({ title: "SFTP 진단 실패: 연결 불가" });
        return finish({
          title: "SFTP 진단 실패: 연결 불가",
          lines: [
            `시각: ${report.at}`,
            `연결: 실패 — ${conn.error}`,
            `진단: ${report.diagnosis}`,
            `구성 요약: ${JSON.stringify(report.config)}`,
          ],
          data: report,
        });
      }
      // 허용 루트 실재 확인 + (선택) 쓰기 프로브
      const roots: any[] = [];
      for (const root of ctx.policy.allowedRoots) {
        const guard = guardPath({ path: root, allowedRoots: ctx.policy.allowedRoots });
        const t = await ctx.transport.resolveTarget(root).catch(() => ({ ok: false, reason: "resolve 실패" }));
        const entry: any = { root, guardOk: guard.ok, guardReason: guard.reason, exists: t.ok, kind: t.ok ? t.kind : null, resolved: t.ok ? t.resolved : null };
        if (args.probeWrite === true && t.ok) {
          const preview = {
            title: `SFTP 쓰기 프로브: ${t.resolved}`,
            patterns: ["SFTP 쓰기 프로브(임시 파일)", `대상 디렉터리: ${t.resolved}`, "이름: .__sftp_guard_probe_* (즉시 삭제)", "§7: bind mount 쓰기 권한 실제 확인"],
            metadata: { filepath: t.resolved },
            text: "",
          };
          const gate = await authorizeGuarded({
            action: ACTION.SCOPE,
            context,
            ctx,
            target: { requested: t.resolved, resolved: t.resolved, kind: "directory", inScope: false, root },
            preview,
            tool: "sftp_doctor",
            audit: { probe: "write", dir: t.resolved },
          });
          const probe = await ctx.transport.probeWrite(t.resolved, ctx.policy.defaultFileMode);
          entry.writeProbe = { approver: gate.approver, ok: probe.ok, cleanedUp: probe.cleanedUp === true, reason: probe.reason };
        }
        roots.push(entry);
      }
      report.roots = roots;
      report.gate = {
        ...ctx.gate.snapshot(),
        hint: `opencode 기본 permission 은 "*": "allow" 이므로 sftp_* 권한에 "ask" 를 명시해야 게이트가 동작한다.`,
      };
      if (args.probeGate === true) {
        const preview = {
          title: "SFTP 승인 게이트 생존 테스트",
          patterns: ["게이트 테스트(실제 파일은 건드리지 않음)", "이 승인이 실제로 뜨면 게이트는 정상 동작 중"],
          metadata: { filepath: "(없음)" },
          text: "",
        };
        const gate = await authorizeGuarded({
          action: ACTION.SCOPE,
          context,
          ctx,
          target: { requested: "(게이트 테스트)", resolved: "(게이트 테스트)", kind: "probe", inScope: false, root: null },
          preview,
          tool: "sftp_doctor",
        });
        report.gate.probe = { ok: gate.ok, approver: gate.approver, reason: gate.reason };
      }
      const deniedByChroot = roots.filter((r) => !r.exists).map((r) => r.root);
      report.chrootWarning =
        deniedByChroot.length > 0
          ? `chroot 안에서 보이지 않는 허용 루트: ${deniedByChroot.join(", ")} — sshd 의 ChrootDirectory 와 bind mount 위치를 확인할 것.`
          : undefined;
      logOutcome(ctx, context, "sftp_doctor", { outcome: "ok", roots: roots.length });
      context.metadata({ title: "SFTP 진단 완료" });
      return finish({
        title: "SFTP 진단 완료",
        lines: [
          `시각: ${report.at}`,
          `연결: ${report.connection.ok ? "성공" : `실패 — ${report.connection.error}`}`,
          `chroot 루트(원격 / 의 실경로): ${report.connection.status?.jailRoot ?? "(확인 못함)"}`,
          ...report.roots.map(
            (r) => `허용 루트 ${r.root}: 존재=${r.exists} 종류=${r.kind ?? "-"} 해석결과=${r.resolved ?? "-"}${r.writeProbe ? ` 쓰기프로브=${r.writeProbe.ok ? "가능" : `불가(${r.writeProbe.reason ?? "원인 미상"})`} 정리=${r.writeProbe.cleanedUp ? "완료" : "실패"}` : ""}`,
          ),
          `승인 게이트: 요청 ${report.gate.stats.asks} / 승인 ${report.gate.stats.approved} / 거부 ${report.gate.stats.rejected} / 타임아웃 ${report.gate.stats.timeouts} / 우회감지 ${report.gate.stats.bypassDetected}`,
          `게이트 실측성 검사: ${report.gate.requireLiveGate ? "켜짐(기본 permission 이 allow 면 거부)" : "꺼짐"} / 이벤트 관측 ${report.gate.sawAnyAskedEvent ? "있음" : "없음"}`,
          report.gate.probe ? `게이트 생존 테스트: ${report.gate.probe.ok ? "통과" : `실패 — ${report.gate.probe.reason}`}` : "게이트 생존 테스트: 미실행(probeGate:true 로 실행)",
          report.diagnosis ? `진단: ${report.diagnosis}` : undefined,
          report.chrootWarning ? `주의: ${report.chrootWarning}` : undefined,
          `구성 요약: ${JSON.stringify(report.config)}`,
        ],
        data: report,
      });
    },
  });

  return {
    sftp_list,
    sftp_read,
    sftp_stat,
    sftp_write_new,
    sftp_edit_existing,
    sftp_delete,
    sftp_move,
    sftp_mkdir,
    sftp_chmod,
    sftp_propose_scope,
    sftp_request_scope_approval,
    sftp_set_mode,
    sftp_doctor,
  };
}

// ── 내부 헬퍼 ────────────────────────────────────────────────────────────────

/** content / contentBase64 → Buffer (둘 다 주면 거부). */
function decodeContentArgs(args, ctx) {
  const hasText = typeof args.content === "string";
  const hasB64 = typeof args.contentBase64 === "string";
  if (hasText === hasB64) throw new Error("content 와 contentBase64 중 정확히 하나만 지정할 것.");
  if (hasText) return Buffer.from(args.content, "utf8");
  try {
    const buf = Buffer.from(args.contentBase64, "base64");
    // base64 는 잘못된 문자를 조용히 버린다 → 대략 검증(길이 0 은 명백한 오류).
    if (buf.length === 0 && args.contentBase64.length > 0) throw new Error("base64 디코딩 결과가 비어 있음");
    return buf;
  } catch (err) {
    throw new Error(`contentBase64 디코딩 실패: ${safeErrorMessage(err)}`);
  }
}

/** 8진수 권한 인자를 정규화. "644"/"0644"/420 → 0o644 */
function normalizeModeArg(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return fallback;
    return value <= 0o7777 ? value : parseInt(String(value), 8);
  }
  const s = String(value).trim();
  if (/^[0-7]+$/.test(s)) return parseInt(s, 8);
  const n = Number(s);
  if (Number.isInteger(n) && n >= 0) return n <= 0o7777 ? n : parseInt(s, 8);
  return fallback;
}

function normalizeModeValue(mode) {
  if (mode === undefined || mode === null) return null;
  if (typeof mode === "number") return mode;
  const s = String(mode);
  if (/^[0-7]+$/.test(s)) return parseInt(s, 8);
  const n = Number(s);
  return Number.isInteger(n) ? n : null;
}

/** 감사자 정책 활성 여부(표시용). */
function policyEnabled(ctx) {
  return ctx.policy?.auditor?.enabled === true;
}

/** 기존 파일 권한을 그대로 유지하기 위한 값(없으면 undefined → ssh2 기본 0o666+umask). */
function preserveMode(attrs) {
  const mode = normalizeModeValue(attrs?.mode);
  return mode && mode > 0 ? mode : undefined;
}

/** 읽기 전용 트리 워크(심볼릭 링크를 따라가지 않는다 — 링크는 이름만 기록). */
async function walkTree(ctx, root, maxDepth, maxEntries) {
  const sample: string[] = [];
  const directories: string[] = [];
  let total = 0;
  let truncated = false;
  const queue: Array<{ path: string; depth: number }> = [{ path: root, depth: 0 }];
  while (queue.length) {
    const { path, depth } = queue.shift()!;
    const listed = await ctx.transport.listDir(path);
    if (!listed.ok) {
      sample.push(`${path} — 목록 실패: ${listed.reason}`);
      continue;
    }
    for (const e of listed.entries) {
      total++;
      if (total > maxEntries) {
        truncated = true;
        break;
      }
      const child = `${path === "/" ? "" : path}/${e.name}`;
      if (depth < maxDepth) sample.push(`${"  ".repeat(depth)}${e.name}${e.type === "dir" ? "/" : e.type === "symlink" ? " -> (링크, 따라가지 않음)" : ` (${humanBytes(e.size ?? 0)})`}`);
      if (e.type === "dir") {
        directories.push(child);
        if (depth < maxDepth) queue.push({ path: child, depth: depth + 1 });
      }
    }
    if (truncated) break;
  }
  return { total: Math.min(total, maxEntries), truncated, sample: sample.slice(0, 400), directories: directories.slice(0, 200), depth: maxDepth };
}
