// 감사 로그 — §6.
// append-only, 로컬 전용(절대로 SFTP 로 보내지 않는다), 용량 상한 + 로테이션,
// 비밀값 미포함(모든 필드는 redact 통과), 이전 해시 체인으로 후속 변조 detectable.
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { nowIso, oneLine, sha256 } from "./util.mjs";
import { scrubDeep, scrubText } from "./redact.mjs";

/** 승인 주체(§6 approver 필드). */
export const APPROVER = {
  HUMAN: "human", // TUI/웹UI 에서 사람이 직접 허용
  AUDITOR: "auditor", // risk-auditor 서브에이전트가 허용(감사자 모드일 때만)
  SCOPE_AUTO: "scope-auto", // 승인된 scope 안이라 자동 허용
  APPROVE_ALL: "approve-all", // approve-all 세션 토글에 의한 자동 허용
  NONE: "none", // 승인 없이 통과(읽기 등 — 그래도 로깅한다)
};

const ZERO_HASH = "0".repeat(64);

export class AuditLog {
  /**
   * @param {{path: string, maxBytes?: number, keepRotations?: number, enabled?: boolean, hashChain?: boolean}} opts
   */
  constructor(opts) {
    this.path = opts.path;
    this.maxBytes = Math.max(64 * 1024, opts.maxBytes ?? 5 * 1024 * 1024);
    this.keepRotations = Math.max(1, opts.keepRotations ?? 3);
    this.enabled = opts.enabled !== false;
    this.hashChain = opts.hashChain !== false;
    this.writeErrors = 0;
    this.lastHash = this.#loadLastHash();
  }

  #loadLastHash() {
    try {
      if (!existsSync(this.path)) return ZERO_HASH;
      if (statSync(this.path).size === 0) return ZERO_HASH;
      // 마지막 줄만 읽는다(대용량 로그에서도 O(1)).
      const tail = readTail(this.path, 8192);
      const lastLine = tail.trimEnd().split("\n").pop() ?? "";
      if (!lastLine) return ZERO_HASH;
      const parsed = JSON.parse(lastLine);
      return typeof parsed.hash === "string" ? parsed.hash : sha256(lastLine);
    } catch {
      return ZERO_HASH;
    }
  }

  /**
   * 항목 하나를 추가한다. 절대 던지지 않는다(로그 실패가 작업 실패로 번지면 안 된다).
   * @param {Record<string, unknown>} entry
   */
  append(entry) {
    if (!this.enabled) return { ok: false, reason: "audit disabled" };
    const record = {
      ts: entry.ts ?? nowIso(),
      ...scrubDeep(entry, { maxDepth: 5, maxString: 2_000 }),
    };
    record.prev = this.lastHash;
    record.hash = this.hashChain ? sha256(`${record.prev}\n${stableStringify(record)}`) : sha256(stableStringify(record));
    this.lastHash = record.hash;
    const line = `${JSON.stringify(record)}\n`;
    try {
      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
      this.#rotateIfNeeded(Buffer.byteLength(line, "utf8"));
      appendFileSync(this.path, line, { encoding: "utf8", mode: 0o600 });
      return { ok: true, hash: record.hash };
    } catch (err) {
      this.writeErrors++;
      return { ok: false, reason: oneLine(scrubText(err?.message ?? String(err)), 200) };
    }
  }

  #rotateIfNeeded(incoming) {
    let size = 0;
    try {
      size = statSync(this.path).size;
    } catch {
      return;
    }
    if (size + incoming <= this.maxBytes) return;
    // audit.log → audit.log.1 → audit.log.2 … 순으로 민다.
    for (let i = this.keepRotations - 1; i >= 1; i--) {
      const from = `${this.path}.${i}`;
      const to = `${this.path}.${i + 1}`;
      if (existsSync(from)) {
        try {
          if (existsSync(to)) rmSync(to, { force: true });
          renameSync(from, to);
        } catch {
          /* 회전 실패는 무시(로그는 best-effort) */
        }
      }
    }
    try {
      if (existsSync(`${this.path}.1`)) rmSync(`${this.path}.1`, { force: true });
      renameSync(this.path, `${this.path}.1`);
    } catch {
      /* noop */
    }
  }

  /** 최근 항목(진단/테스트용). */
  tail(n = 20) {
    try {
      const text = readFileSync(this.path, "utf8");
      return text
        .trimEnd()
        .split("\n")
        .filter(Boolean)
        .slice(-n)
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return { parseError: true, line: l.slice(0, 200) };
          }
        });
    } catch {
      return [];
    }
  }

  /** 체인 무결성 검증(변조 감지). */
  verifyChain() {
    let prev = ZERO_HASH;
    let count = 0;
    for (const entry of this.tail(1_000_000)) {
      count++;
      if (entry.parseError) return { ok: false, brokenAt: count, reason: "파싱 불가 줄" };
      const { hash, ...rest } = entry;
      if (rest.prev !== prev) return { ok: false, brokenAt: count, reason: "prev 불일치(줄 삭제/삽입 또는 변조)" };
      const expected = this.hashChain ? sha256(`${prev}\n${stableStringify(rest)}`) : sha256(stableStringify(rest));
      if (expected !== hash) return { ok: false, brokenAt: count, reason: "hash 불일치(내용 변조)" };
      prev = hash;
    }
    return { ok: true, entries: count };
  }

  /** 테스트용 초기화. */
  reset() {
    try {
      writeFileSync(this.path, "", { mode: 0o600 });
      this.lastHash = ZERO_HASH;
    } catch {
      /* noop */
    }
  }
}

function readTail(path, maxBytes) {
  const fd = openSync(path, "r");
  try {
    const size = statSync(path).size;
    const want = Math.min(maxBytes, size);
    const buf = Buffer.allocUnsafe(want);
    readSync(fd, buf, 0, want, size - want);
    return buf.toString("utf8");
  } finally {
    closeSync(fd);
  }
}

function stableStringify(obj) {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

/** 로그 기본 경로(XDG). */
export function defaultAuditPath(env = process.env) {
  const stateHome = env.XDG_STATE_HOME || join(env.HOME || "/tmp", ".local", "state");
  return join(stateHome, "opencode", "sftp-guard", "audit.log");
}
