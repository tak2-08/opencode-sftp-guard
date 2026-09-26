// 승인 매트릭스 판정 엔진 — §2. 순수 함수(네트워크/디스크 없음)라 단위 테스트가 가능하다.
//
// 이 파일은 "무엇을 할 수 있는가"만 정한다. "실제로 허가를 받았는가"는 상위 계층(gate.ts)이
// 확인한다. 두 계층을 분리한 이유: 판정 로직의 오류를 UI/SDK 버그와 섞지 않기 위해서.
import { APPROVER } from "./audit.mjs";
import { RISK } from "./classify.mjs";
import { humanBytes } from "./util.mjs";

/** 액션 종류. */
export const ACTION = {
  LIST: "list",
  READ: "read",
  WRITE_NEW: "write_new",
  WRITE_EDIT: "write_edit",
  MKDIR: "mkdir",
  DELETE: "delete",
  MOVE: "move",
  CHMOD: "chmod",
  SCOPE: "scope",
  MODE: "mode",
};

/** 판정 결과. */
export const DECISION = {
  ALLOW: "allow", // 게이트 없이 통과(로그는 남김)
  ASK: "ask", // 인간(또는 감사자) 승인이 필요
  DENY: "deny", // 코드 차원에서 거부(게이트로 승인을 얻을 수 없음)
};

/** opencode permission 이름(§5 네이티브 훅에서 쓰는 키). */
export const PERMISSION = {
  READ: "sftp_read",
  WRITE: "sftp_write",
  MKDIR: "sftp_mkdir",
  DELETE: "sftp_delete",
  MOVE: "sftp_move",
  CHMOD: "sftp_chmod",
  SCOPE: "sftp_scope",
  MODE: "sftp_mode",
  PROBE: "sftp_probe",
};

/**
 * §2 매트릭스.
 *
 * @param {object} input
 * @param {string} input.action ACTION.*
 * @param {object} [input.classification] classifyTarget() 결과(쓰기 계열에서 필수)
 * @param {object} input.target { requested, resolved, kind, inScope, root }
 * @param {object} [input.hardDenied] isHardDeniedTarget() 결과
 * @param {object} input.session { discoveryRoot, scopePaths, approveAll, auditorMode, autoApprovedCount, batchCap }
 * @param {object} [input.policy] 정책(denyHardContentWrites 등)
 * @returns {{decision: string, approver?: string, permission?: string, reason: string,
 *            canAuditorApprove?: boolean, risk?: string, alwaysPattern?: string}}
 */
export function decide(input) {
  const { action, target, session, policy = {}, hardDenied } = input;
  const cls = input.classification ?? null;
  const inScope = Boolean(target?.inScope) || withinSessionRoot(session, target?.resolved);
  const risk = cls?.risk ?? RISK.STATIC;

  // ── 읽기 계열 ──────────────────────────────────────────────────────────────
  if (action === ACTION.LIST || action === ACTION.READ) {
    if (target?.kind === "outside-root") {
      return { decision: DECISION.DENY, reason: "허용 루트 밖 경로 — chroot 두 트리 밖 접근 불가(§0.1)" };
    }
    if (inScope) {
      return {
        decision: DECISION.ALLOW,
        approver: APPROVER.SCOPE_AUTO,
        reason: `읽기가 승인된 탐색 범위 안: ${target.resolved}`,
        risk,
      };
    }
    // 범위 밖 읽기 → 범위 확장 플로우(§2 2행, §3 5행)
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.SCOPE,
      approver: APPROVER.HUMAN,
      reason: `읽기 대상이 현재 승인 범위 밖: ${target?.resolved ?? "(미정)"} — 이 경로(또는 상위 폴더)를 범위에 추가할지 확인 필요.`,
      canAuditorApprove: false,
      risk,
    };
  }

  // ── 범위 승인 자체 ─────────────────────────────────────────────────────────
  if (action === ACTION.SCOPE) {
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.SCOPE,
      approver: APPROVER.HUMAN,
      reason: "범위 승인은 항상 인간 확인이 필요하다(§3).",
      canAuditorApprove: false,
    };
  }

  // ── 모드 변경(approve-all / 감사자 모드) ──────────────────────────────────
  if (action === ACTION.MODE) {
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.MODE,
      approver: APPROVER.HUMAN,
      reason: "권한 격하/상향은 모두 인간 확인 대상이다.",
      canAuditorApprove: false,
    };
  }

  // ── 삭제: 항상 파일별 질문. scope/approve-all/감사자 override 없음(§2) ─────
  if (action === ACTION.DELETE) {
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.DELETE,
      approver: APPROVER.HUMAN,
      reason: "삭제는 파일별 항상 승인(오버라이드 없음, §2).",
      canAuditorApprove: false,
      risk,
    };
  }

  // ── 이동/이름변경: 동일(§2) ───────────────────────────────────────────────
  if (action === ACTION.MOVE) {
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.MOVE,
      approver: APPROVER.HUMAN,
      reason: "이동/이름변경은 파일별 항상 승인(오버라이드 없음, §2).",
      canAuditorApprove: false,
      risk,
    };
  }

  // ── chmod ─────────────────────────────────────────────────────────────────
  if (action === ACTION.CHMOD) {
    const addsExec = Boolean(cls?.pathAnalysis?.addsExecuteBit) || Boolean(input.addsExecuteBit);
    if (risk === RISK.HARD || addsExec) {
      return {
        decision: DECISION.ASK,
        permission: PERMISSION.CHMOD,
        approver: hardDenied?.denied ? APPROVER.HUMAN : session.auditorMode ? APPROVER.AUDITOR : APPROVER.HUMAN,
        reason: addsExec
          ? "실행 비트 추가로 서버 실행 가능성이 생김 → 고위험과 동등 처리(§1)."
          : "권한 변경 대상이 고위험 파일.",
        canAuditorApprove: !hardDenied?.denied && Boolean(session.auditorMode),
        risk,
      };
    }
    if (inScope) {
      return { decision: DECISION.ALLOW, approver: APPROVER.SCOPE_AUTO, reason: `실행 비트 없는 chmod, 승인 범위 안: ${target.resolved}`, risk };
    }
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.CHMOD,
      approver: APPROVER.HUMAN,
      reason: "범위 밖 chmod 은 확인이 필요하다.",
      canAuditorApprove: false,
      risk,
    };
  }

  // ── mkdir ─────────────────────────────────────────────────────────────────
  if (action === ACTION.MKDIR) {
    if (inScope) return { decision: DECISION.ALLOW, approver: APPROVER.SCOPE_AUTO, reason: `mkdir, 승인 범위 안: ${target.resolved}` };
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.MKDIR,
      approver: APPROVER.HUMAN,
      reason: "범위 밖 디렉터리 생성은 확인이 필요하다(§2).",
      canAuditorApprove: false,
    };
  }

  // ── 쓰기(신규/편집) ──────────────────────────────────────────────────────
  if (action === ACTION.WRITE_NEW || action === ACTION.WRITE_EDIT) {
    // 웹서버 설정/실행 비트는 deny-list.
    if (hardDenied?.denied) {
      if (policy.denyHardContentWrites && risk === RISK.HARD) {
        return {
          decision: DECISION.DENY,
          reason: `deny-list 대상이라 코드에서 거부: ${hardDenied.why}`,
          risk,
        };
      }
      return {
        decision: DECISION.ASK,
        permission: PERMISSION.WRITE,
        approver: APPROVER.HUMAN, // 감사자 override 불가(§4)
        reason: `deny-list 대상 — 반드시 인간이 직접 확인해야 한다: ${hardDenied.why}`,
        canAuditorApprove: false,
        risk,
      };
    }

    if (risk === RISK.HARD || risk === RISK.HIGH) {
      return {
        decision: DECISION.ASK,
        permission: PERMISSION.WRITE,
        approver: session.auditorMode ? APPROVER.AUDITOR : APPROVER.HUMAN,
        reason: `고위험 쓰기 — 항상 승인 필요(§2). 범위로 예외되지 않는다: ${cls.summary}`,
        // ★ 방어심: risk HARD 는 §4 deny-list 와 같은 집합이다. hardDenied 결과가 전달되지 않았거나
        //   판정 로직이 바뀌어도, 감사자는 HARD 를 통과시킬 수 없다.
        canAuditorApprove: risk !== RISK.HARD && Boolean(session.auditorMode),
        risk,
      };
    }

    // static 파일
    if (session.approveAll) {
      const cap = session.batchCap ?? 20;
      if ((session.autoApprovedCount ?? 0) >= cap) {
        return {
          decision: DECISION.ASK,
          permission: PERMISSION.WRITE,
          approver: APPROVER.HUMAN,
          reason:
            `approve-all 자동 허용 한도 도달(${session.autoApprovedCount}/${cap}) — §5 배치 상한에 따라 ` +
            `이제부터는 명시적 확인 없이 자동 허용하지 않는다.`,
          canAuditorApprove: false,
          risk,
        };
      }
      return {
        decision: DECISION.ALLOW,
        approver: APPROVER.APPROVE_ALL,
        reason: `approve-all 세션 토글 + static 파일(자동 허용·로그 기록) [${session.autoApprovedCount + 1}/${cap}]`,
        risk,
      };
    }
    if (inScope) {
      return { decision: DECISION.ALLOW, approver: APPROVER.SCOPE_AUTO, reason: `static 파일 쓰기, 승인 범위 안: ${target.resolved}`, risk };
    }
    return {
      decision: DECISION.ASK,
      permission: PERMISSION.WRITE,
      approver: APPROVER.HUMAN,
      reason: "범위 밖 static 파일 쓰기 — 파일별 확인이 필요하다(§2).",
      canAuditorApprove: false,
      risk,
    };
  }

  // 알 수 없는 액션 = fail closed.
  return { decision: DECISION.DENY, reason: `알 수 없는 액션: ${action} (fail-closed)` };
}

/** 세션 탐색 루트(§3 1단계: 사람이 준 base path) 안인지. */
function withinSessionRoot(session, resolved) {
  if (!session?.discoveryRoot || !resolved) return false;
  const root = session.discoveryRoot.replace(/\/+$/, "");
  const t = String(resolved).replace(/\/+$/, "");
  return t === root || t.startsWith(`${root}/`);
}

// ─────────────────────────────────────────────────────────────────────────────
// §5 승인 미리보기 빌더
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 쓰기/편집 승인 미리보기. "파일 이름만 물어보는 일" 이 없도록 내용 맥락을 반드시 포함한다.
 * @returns {{title: string, patterns: string[], metadata: object, text: string}}
 */
export function buildWritePreview(input) {
  const { target, classification, diff, beforeSha, afterSha, action, expected } = input;
  const verb = action === ACTION.WRITE_NEW ? "신규 파일 작성" : "기존 파일 수정";
  const riskLabel =
    classification?.risk === RISK.HARD ? "⛔ HARD-DENY(감사자 승인 불가)" : classification?.risk === RISK.HIGH ? "⚠ HIGH-RISK" : "static";
  const head = `${verb} — ${riskLabel}`;
  const title = `SFTP ${head}: ${target.resolved}`;
  const lines = [];
  lines.push(`${head}`);
  lines.push(`대상: ${target.resolved}`);
  if (target.requested && target.requested !== target.resolved) lines.push(`요청 경로: ${target.requested} (심볼릭 링크 해석됨)`);
  lines.push(`크기: ${humanBytes(diff?.afterBytes ?? 0)}${diff?.binary ? " (바이너리)" : ""}`);
  if (beforeSha) lines.push(`이전 sha256: ${beforeSha.slice(0, 16)}…`);
  if (afterSha) lines.push(`이후 sha256: ${afterSha.slice(0, 16)}…`);
  if (diff && !diff.binary) lines.push(`변경량: +${diff.added} -${diff.removed} (유지 ${diff.unchanged}줄)`);
  if (classification?.summary) lines.push(`분류 근거: ${classification.summary}`);
  if (expected?.retriesLeft !== undefined) lines.push(`감사자 재시도 잔여: ${expected.retriesLeft}`);
  if (classification?.contentScan?.hard?.length) {
    lines.push(`치명적 시그니처: ${classification.contentScan.hard.map((h) => `${h.why} <-- "${h.sample}"`).join(" ; ")}`);
  }
  const text = diff?.text ? `${lines.join("\n")}\n\n${diff.text}` : lines.join("\n");
  return {
    title,
    // patterns 는 opencode 승인 UI 와 "always" 규칙에 쓰인다 → 사람이 읽는 요약으로 채운다.
    patterns: [lines[0], ...lines.slice(1, 5)],
    metadata: {
      filepath: target.resolved,
      diff: diff?.binary ? "(binary payload — 본문 미표시)" : diff?.text ?? "",
      risk: classification?.risk ?? RISK.STATIC,
      sftpPreview: { lines, diffText: diff?.binary ? undefined : diff?.text },
    },
    text,
  };
}

/** 삭제 미리보기(크기+해시+내용 머리). */
export function buildDeletePreview(input) {
  const { target, stat, sha256: digest, head } = input;
  const lines = [
    "파일 삭제(되돌릴 수 없음)",
    `대상: ${target.resolved}`,
    `종류: ${stat?.isDirectory ? "디렉터리" : "파일"} / 크기: ${humanBytes(stat?.size ?? 0)}`,
    `sha256: ${String(digest ?? "미확인").slice(0, 16)}…`,
  ];
  if (head) lines.push("내용 앞부분:", ...String(head).split("\n").slice(0, 20).map((l) => `  ${l}`));
  return {
    title: `SFTP 삭제: ${target.resolved}`,
    patterns: lines,
    metadata: { filepath: target.resolved, sftpPreview: { lines } },
    text: lines.join("\n"),
  };
}

/** 이동 미리보기(출발+도착+크기). */
export function buildMovePreview(input) {
  const { from, to, stat, sha256: digest, overwrite } = input;
  const lines = [
    "파일 이동/이름변경",
    `출발: ${from}`,
    `도착: ${to}`,
    `크기: ${humanBytes(stat?.size ?? 0)} / sha256: ${String(digest ?? "미확인").slice(0, 16)}…`,
    overwrite ? "기존 도착 파일을 덮어쓴다(원자적 posix-rename, 실패 시 조용히 지우지 않는다)" : "도착 파일이 없음",
  ];
  return {
    title: `SFTP 이동: ${from} → ${to}`,
    patterns: lines,
    metadata: { filepath: from, sftpPreview: { lines } },
    text: lines.join("\n"),
  };
}

/** chmod 미리보기. */
export function buildChmodPreview(input) {
  const { target, beforeMode, afterMode, addsExecuteBit } = input;
  const lines = [
    addsExecuteBit ? "권한 변경(실행 비트 추가 — 고위험)" : "권한 변경",
    `대상: ${target.resolved}`,
    `${octal(beforeMode)} → ${octal(afterMode)}`,
    addsExecuteBit ? "실행 비트가 붙으면 웹서버가 이 파일을 실행할 수 있다" : "실행 비트 없음",
  ];
  return {
    title: `SFTP chmod: ${target.resolved} ${octal(beforeMode)}→${octal(afterMode)}`,
    patterns: lines,
    metadata: { filepath: target.resolved, sftpPreview: { lines } },
    text: lines.join("\n"),
  };
}

/** 범위 승인 미리보기(모호한 서술 대신 명시적 목록 — §3 3단계). */
export function buildScopePreview(input) {
  const { paths, basePath, entries } = input;
  const lines = [`SFTP 작업 범위 승인 요청 — 아래 경로만 자동 허용됨`, `기준 경로: ${basePath}`];
  for (const p of paths) {
    const kindLabel = p.kind === "directory" ? "폴더" : p.kind === "absent" ? "새 폴더/경로" : "파일";
    lines.push(`  • ${p.path}  [${kindLabel}]${p.note ? ` — ${p.note}` : ""}`);
  }
  if (entries) {
    lines.push(`탐색 결과: 항목 ${entries.total}개, 최대 깊이 ${entries.depth}, 절단 여부 ${entries.truncated ? "예" : "아니오"}`);
    for (const sample of entries.sample ?? []) lines.push(`    - ${sample}`);
  }
  lines.push("범위 밖 경로로 가려면 다시 승인을 물어본다(§3 5단계).");
  return {
    title: `SFTP 범위 승인: ${paths.length}개 경로`,
    patterns: lines.slice(0, 8),
    metadata: { sftpPreview: { lines } },
    text: lines.join("\n"),
  };
}

/** 모드 변경 미리보기. */
export function buildModePreview(input) {
  const { changes, current } = input;
  const lines = ["SFTP 세션 모드 변경 요청", ...changes.map((c) => `  • ${c}`), `현재: ${current}`];
  return {
    title: `SFTP 모드 변경: ${changes.join(", ")}`,
    patterns: lines,
    metadata: { sftpPreview: { lines } },
    text: lines.join("\n"),
  };
}

function octal(mode) {
  if (mode === null || mode === undefined) return "(알 수 없음)";
  const n = typeof mode === "number" ? mode : parseInt(String(mode), 8);
  return Number.isFinite(n) ? `0${(n & 0o7777).toString(8).padStart(3, "0")}` : "(알 수 없음)";
}
