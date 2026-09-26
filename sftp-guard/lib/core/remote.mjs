// 원격 SFTP 전송 계층 — 런타임 독립(runtime-agnostic).
//
// 이 모듈은 opencode 를 모른다. 그래서 (1) Node 테스트 하네스로 실제 SFTP 서버를 상대로
// 검증할 수 있고, (2) opencode 의 Bun 프로세스에서도 그대로 돈다.
//
// 보안 관련 계약:
//  - 연결 객체(ssh2-sftp-client 인스턴스)는 이 모듈이 만든 클로저 안에만 존재한다.
//    호출자는 문자열 경로/버퍼만 건넨다.
//  - 이 레이어는 그 자체로 게이트가 아니다(§0: 게이트는 각 툴의 execute 안에서 enforced).
//    다만 "경로 해석"은 이 레이어가 강제한다(§7): 허용 루트 밖이면 어떤 메서드도 원격 호출을 못 한다.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { guardPath, matchScope, splitParent, whichRoot } from "./paths.mjs";
import { safeErrorMessage, scrubText } from "./redact.mjs";
import { humanBytes, looksBinary, sha256 } from "./util.mjs";

// ssh2-sftp-client 은 CommonJS 이고 타입이 없다. 런타임에는 문제없으므로 require 로 로드한다.
const requireCjs = createRequire(import.meta.url);
let SftpClientCtor;
function loadClientCtor() {
  if (SftpClientCtor) return SftpClientCtor;
  const mod = requireCjs("ssh2-sftp-client");
  SftpClientCtor = mod?.default ?? mod;
  if (typeof SftpClientCtor !== "function") throw new Error("ssh2-sftp-client 로드를 실패했습니다(모듈 형태가 예상과 다름)");
  return SftpClientCtor;
}

/** 원격 오류 코드 → 사람이 읽을 메시지(§7 "permission-denied 는 명확한 오류로"). */
const ERROR_HINTS = {
  EACCES: "원격 쓰기 권한 거부(denied) — SFTP 계정이 해당 경로의 소유 그룹에 속해야 합니다(id -Gn, chown/chgrp 확인).",
  EPERM: "원격 권한 거부(denied) — 파일 소유자/그룹 또는 상위 디렉터리 쓰기 권한 문제.",
  ENOENT: "원격 경로 없음 — 부모 디렉터리를 먼저 만들었는지 확인하세요.",
  EEXIST: "원격 경로가 이미 존재 — sftp_write_new 은 기존 파일을 덮어쓰지 않습니다.",
  EACCES_DIR: "디렉터리 접근 불가",
  ENOTDIR: "경로 중간에 디렉터리가 아님",
  EISDIR: "대상이 디렉터리임(파일로 취급됨)",
  ELOOP: "심볼릭 링크 루프",
  EFBIG: "파일 크기 제한 초과",
  ENOSPC: "원격 디스크 공간 부족",
  EDQUOT: "원격 쿼터(용량) 초과",
  EHOSTUNREACH: "호스트 도달 불가 — §0.1: 컨테이너→호스트 루프백(127.0.0.1:22 / host.docker.internal:22) 경로와 Docker 네트워크 정책 확인.",
  ECONNREFUSED: "연결 거부 — 호스트의 sshd가 해당 주소/포트에서 listening 하는지, Docker 네트워크가 이 포트를 차단하지 않는지 확인.",
  ETIMEDOUT: "연결 시간 초과 — 방화벽/네트워크 정책 또는 readyTimeout 설정 확인.",
  ENOTFOUND: "호스트 이름 해석 실패 — IP 또는 docker 네트워크 별칭 확인.",
};

export class SftpTransport {
  /**
   * @param {{connection: object, allowedRoots: string[], connectRetries?: number, onEvent?: (e: object) => void}} opts
   */
  constructor(opts) {
    this.connection = opts.connection;
    this.allowedRoots = opts.allowedRoots ?? [];
    this.connectRetries = Math.max(0, opts.connectRetries ?? 1);
    this.onEvent = opts.onEvent ?? (() => {});
    /** @type {any} ssh2-sftp-client 인스턴스 — 플러그인 클로저 밖으로 나가지 않는다. */
    this.client = null;
    this.connectPromise = null;
    this.lastError = null;
    this.connectedAt = 0;
    /** 경로별 in-process 직렬화 잠금(같은 파일 동시 쓰기 방지). */
    this.locks = new Map();
  }

  /** 연결(지연 생성). 실패해도 예외 대신 상태를 반환한다. */
  async ensureConnected() {
    if (this.client) return { ok: true, reused: true };
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = this.#connectWithRetry().finally(() => {
      this.connectPromise = null;
    });
    return this.connectPromise;
  }

  async #connectWithRetry() {
    let lastErr = null;
    for (let attempt = 0; attempt <= this.connectRetries; attempt++) {
      try {
        return await this.#connectOnce();
      } catch (err) {
        lastErr = err;
        this.lastError = safeErrorMessage(err);
        this.#safeEnd();
        if (attempt < this.connectRetries) await sleep(500 * (attempt + 1));
      }
    }
    return { ok: false, error: this.lastError };
  }

  async #connectOnce() {
    const Ctor = loadClientCtor();
    // 기본 콜백은 console.error/console.log 로 새어 나간다 → 전부 무음 + 내부 기록으로 교체.
    const client = new Ctor("sftp-guard", {
      error: (err) => this.#note("client-error", safeErrorMessage(err)),
      end: () => this.#note("client-end", "연결 종료 이벤트"),
      close: () => this.#note("client-close", "연결 닫힘 이벤트"),
    });
    const cfg = {
      host: this.connection.host,
      port: this.connection.port,
      username: this.connection.username,
      readyTimeout: this.connection.readyTimeoutMs,
      keepaliveInterval: this.connection.keepaliveIntervalMs,
      keepaliveCountMax: this.connection.keepaliveCountMax,
    };
    if (this.connection.privateKeyPath) {
      // 개인키는 여기서만 읽어서 메모리에 올린다(디스크 경로가 로그에 남지 않게 한다).
      cfg.privateKey = readFileSync(this.connection.privateKeyPath);
    }
    if (this.connection.password) cfg.password = this.connection.password;
    if (this.connection.passphrase) cfg.passphrase = this.connection.passphrase;
    if (this.connection.algorithms) cfg.algorithms = this.connection.algorithms;

    try {
      await client.connect(cfg);
    } catch (err) {
      this.#safeEndClient(client);
      throw enrichConnectError(err, this.connection);
    }
    this.client = client;
    this.connectedAt = Date.now();
    this.#note("connected", `연결 성공 host=${this.connection.host}:${this.connection.port} user=${this.connection.username}`);
    // chroot 안에서의 실제 루트를 확인한다(진단용).
    try {
      const jailRoot = await client.realPath("/");
      this.jailRoot = jailRoot;
    } catch {
      this.jailRoot = null;
    }
    return { ok: true, jailRoot: this.jailRoot };
  }

  #note(kind, message) {
    try {
      this.onEvent({ kind, message: scrubText(message) });
    } catch {
      /* 이벤트 핸들러 오류는 전송 계층을 죽이지 않는다 */
    }
  }

  #safeEnd() {
    if (this.client) {
      this.#safeEndClient(this.client);
      this.client = null;
    }
  }

  #safeEndClient(client) {
    try {
      client.end();
    } catch {
      /* noop */
    }
  }

  async close() {
    this.#safeEnd();
    this.connectedAt = 0;
  }

  /** 진단 정보(비밀 없음). */
  status() {
    return {
      connected: Boolean(this.client),
      connectedAt: this.connectedAt || null,
      jailRoot: this.jailRoot ?? null,
      lastError: this.lastError,
    };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 경로 해석(§7). 아래 메서드들은 모두 resolveTarget() 을 먼저 통과해야 한다.
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * 모델이 준 경로를 (1) 어휘론적으로 정규화하고 (2) 허용 루트 안인지 확인하고
   * (3) realpath 로 심볼릭 링크를 따라가 jail/scope 이탈을 차단한다.
   *
   * @param {string} rawPath
   * @param {{mustExist?: boolean, scopePaths?: string[]}} [opts]
   * @returns {Promise<{ok: boolean, requested?: string, resolved?: string, root?: string, kind?: string, attrs?: object, inScope?: boolean, reason?: string}>}
   */
  async resolveTarget(rawPath, opts = {}) {
    const guard = guardPath({ path: rawPath, allowedRoots: this.allowedRoots });
    if (!guard.ok) return { ok: false, requested: String(rawPath ?? ""), reason: guard.reason };
    const requested = guard.path;
    const root = guard.root;

    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, requested, reason: `SFTP 연결 실패: ${conn.error}` };

    // 3a) 대상이 존재하면 그것을 realpath 한다.
    let resolved = await this.#tryRealPath(requested);
    let kind = "unknown";
    let attrs = null;
    if (resolved) {
      kind = "file";
      try {
        attrs = await this.client.stat(resolved);
        kind = attrs.isDirectory ? "directory" : attrs.isFile ? "file" : "special";
      } catch {
        kind = "file";
      }
    } else {
      // 3b) 존재하지 않으면(생성 대상) 부모를 realpath 한다 → 심볼릭 링크로tree 탈출 차단.
      const { dir, base } = splitParent(requested);
      const resolvedDir = await this.#tryRealPath(dir);
      if (!resolvedDir) {
        return { ok: false, requested, reason: `부모 디렉터리를 확인할 수 없음: ${dir} (없거나 접근 불가)` };
      }
      resolved = `${resolvedDir === "/" ? "" : resolvedDir}/${base}`;
      kind = "absent";
    }

    // realpath 결과는 jail 밖이어서는 안 된다(심볼릭 링크·마운트 우회 최종 차단).
    const resolvedRoot = whichRoot(this.allowedRoots, resolved);
    if (!resolvedRoot) {
      return {
        ok: false,
        requested,
        resolved,
        reason:
          `심볼릭 링크/마운트를 따라간 결과가 허용 루트 밖이다: ${resolved} → ` +
          `허용: ${this.allowedRoots.join(", ")} (§7 경로 이탈 차단)`,
      };
    }

    if (opts.mustExist && kind === "absent") {
      return { ok: false, requested, resolved, reason: `대상이 존재하지 않음: ${resolved}` };
    }

    const inScope = opts.scopePaths ? matchScope(opts.scopePaths, resolved).inScope : null;
    return { ok: true, requested, resolved, root: resolvedRoot, kind, attrs, inScope };
  }

  async #tryRealPath(p) {
    try {
      const r = await this.client.realPath(p);
      return r && r !== "" ? r : null;
    } catch (err) {
      // realPath 는 없는 경로에 대해 "" 를 돌려준다. 그 밖 오류는 감추지 않는다.
      const msg = safeErrorMessage(err);
      if (/No such file|notexist/i.test(msg)) return null;
      throw new Error(`realPath 실패(${p}): ${msg}`);
    }
  }

  /** 특정 경로에 대한 in-process 상호배제(동일 파일 동시 쓰기 방지, §7). */
  async withPathLock(lockKey, fn) {
    const prev = this.locks.get(lockKey) ?? Promise.resolve();
    let release;
    const current = new Promise((r) => {
      release = r;
    });
    this.locks.set(
      lockKey,
      prev.then(() => current),
    );
    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
      // 정리: 자기 자신만 남았으면 맵에서 제거
      queueMicrotask(() => {
        const cur = this.locks.get(lockKey);
        if (cur) {
          Promise.resolve(cur).then(() => {
            if (this.locks.get(lockKey) === cur) this.locks.delete(lockKey);
          }, () => {});
        }
      });
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 읽기
  // ───────────────────────────────────────────────────────────────────────────

  /** @returns {Promise<{ok: boolean, buffer?: Buffer, sha256?: string, size?: number, reason?: string}>} */
  async readFile(resolvedPath, maxBytes) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      const stat = await this.client.stat(resolvedPath);
      if (stat.isDirectory) return { ok: false, reason: `디렉터리는 읽을 수 없음: ${resolvedPath}` };
      if (stat.size > maxBytes) {
        // 전체를 받지 않고 상한만 알려준다(트랜스크립트 폭주 방지).
        return { ok: false, reason: `파일이 너무 큼: ${humanBytes(stat.size)} > 허용 ${humanBytes(maxBytes)}`, size: stat.size };
      }
      const buf = await this.client.get(resolvedPath);
      const buffer = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), "utf8");
      return { ok: true, buffer, sha256: sha256(buffer), size: buffer.length, mtime: stat.modifyTime };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "read") };
    }
  }

  /** @returns {Promise<{ok: boolean, entries?: Array<object>, reason?: string}>} */
  async listDir(resolvedPath) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      const entries = await this.client.list(resolvedPath);
      return {
        ok: true,
        entries: (entries ?? []).map((e) => ({
          name: e.name,
          type: e.type === "d" ? "dir" : e.type === "-" ? "file" : e.type === "l" ? "symlink" : e.type,
          size: e.size,
          modifyTime: e.modifyTime,
          rights: e.rights,
        })),
      };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "list") };
    }
  }

  async stat(resolvedPath) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      const s = await this.client.stat(resolvedPath);
      return {
        ok: true,
        attrs: {
          size: s.size,
          mode: s.mode,
          isDirectory: s.isDirectory,
          isFile: s.isFile,
          isSymbolicLink: s.isSymbolicLink,
          modifyTime: s.modifyTime,
          accessTime: s.accessTime,
          owner: s.uid,
          group: s.gid,
        },
      };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "stat") };
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 쓰기(§7 "network drop mid-write" 대응 포함)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * 새 파일 생성. flags 'wx' 로 원자적 no-clobber 를 보장한다(덮어쓰기 없음).
   * @param {string} resolvedPath
   * @param {Buffer} content
   * @param {number} mode
   */
  async writeNewFile(resolvedPath, content, mode) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      await this.client.put(content, resolvedPath, { writeStreamOptions: { flags: "wx", mode } });
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "write"), stage: "open" };
    }
    return this.verifyWritten(resolvedPath, content);
  }

  /**
   * 기존 파일 덮어쓰기.
   * @param {string} resolvedPath
   * @param {Buffer} content
   * @param {number} mode
   * @param {{expectedSha256?: string, backup?: Buffer}} [opts] expectedSha256 로 낙관적 동시성 제어
   */
  async overwriteFile(resolvedPath, content, mode, opts = {}) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    if (opts.expectedSha256) {
      // 다른 세션이 먼저 바꿨다면 덮어쓰지 않는다(§7 동시 세션).
      const current = await this.readFile(resolvedPath, Number.MAX_SAFE_INTEGER);
      if (!current.ok) return { ok: false, reason: `기존 파일을 읽지 못함(동시성 검사): ${current.reason}` };
      if (current.sha256 !== opts.expectedSha256) {
        return {
          ok: false,
          stage: "concurrency",
          reason:
            `다른 세션/사람이 파일을 이미 바꿈(기대 sha256=${opts.expectedSha256.slice(0, 12)}…, ` +
            `현재 sha256=${String(current.sha256).slice(0, 12)}…). 덮어쓰지 않았다 — 다시 읽고 다시 판단할 것.`,
          currentSha256: current.sha256,
        };
      }
    }
    try {
      await this.client.put(content, resolvedPath, { writeStreamOptions: { flags: "w", mode } });
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "write"), stage: "open" };
    }
    const verify = await this.verifyWritten(resolvedPath, content);
    // 검증 실패 시 원래 내용으로 되돌린다(가능하면).
    if (!verify.ok && Buffer.isBuffer(opts.backup)) {
      try {
        await this.client.put(opts.backup, resolvedPath, { writeStreamOptions: { flags: "w", mode } });
        verify.rolledBack = true;
      } catch {
        verify.rolledBack = false;
      }
    }
    return verify;
  }

  /**
   * 쓰기 직후 원격 무결성 검증(§7: "non-error return 라고 성공을 가정하지 않는다").
   * stat 으로 크기를, 재읽기로 sha256 을 확인한다.
   */
  async verifyWritten(resolvedPath, content) {
    try {
      const stat = await this.client.stat(resolvedPath);
      if (stat.size !== content.length) {
        return {
          ok: false,
          stage: "verify",
          reason: `쓰기 후 크기 불일치: 원격 ${stat.size}B vs 전송 ${content.length}B — 전송 중 연결이 끊겼을 수 있다(부분 기록).`,
        };
      }
      const buf = await this.client.get(resolvedPath);
      const buffer = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), "utf8");
      const digest = sha256(buffer);
      const expected = sha256(content);
      if (digest !== expected) {
        return {
          ok: false,
          stage: "verify",
          reason: `쓰기 후 해시 불일치: 원격 sha256=${digest.slice(0, 12)}… vs 전송 ${expected.slice(0, 12)}… — 원격 파일이 손상되었거나 중간에 변경됨.`,
        };
      }
      return { ok: true, sha256: digest, size: content.length, mode: stat.mode };
    } catch (err) {
      return { ok: false, stage: "verify", reason: this.#explain(err, "verify") };
    }
  }

  async mkdir(resolvedPath, recursive, mode) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      await this.client.mkdir(resolvedPath, recursive);
      if (mode !== undefined && mode !== null) await this.client.chmod(resolvedPath, mode).catch(() => {});
      const stat = await this.client.stat(resolvedPath).catch(() => null);
      return { ok: Boolean(stat?.isDirectory), mode: stat?.mode };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "mkdir") };
    }
  }

  async deleteFile(resolvedPath) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      await this.client.delete(resolvedPath);
      // 실제로 사라졌는지 확인(삭제 "성공" 신뢰 금지).
      const still = await this.#tryRealPath(resolvedPath);
      if (still) return { ok: false, stage: "verify", reason: `삭제 후에도 경로가 남음: ${resolvedPath}` };
      return { ok: true };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "delete") };
    }
  }

  /**
   * 이동/이름변경. OpenSSH 는 posix-rename(원자적 덮어쓰기)을 지원하므로 우선 사용하고,
   * 미지원 서버면 일반 rename 으로 물러난다(그 경우 대상 존재 시 실패 = 안전).
   * @param {string} fromResolved @param {string} toResolved @param {boolean} overwrite
   */
  async move(fromResolved, toResolved, overwrite) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    const toExists = Boolean(await this.#tryRealPath(toResolved));
    if (toExists && !overwrite) {
      return { ok: false, stage: "precheck", reason: `이동 대상이 이미 존재함: ${toResolved} (overwrite:true 를 명시할 것)` };
    }
    try {
      if (toExists && overwrite) {
        try {
          await this.client.posixRename(fromResolved, toResolved);
        } catch {
          // posix-rename 미지원 서버: 기존 대상을 먼저 지우고(동의 없이 지우지 않기 위해 확인 후) 재시도하지 않는다.
          // 대상이 존재하는 덮어쓰기는 여기서 실패시킨다 — 조용히 지우지 않는다.
          return {
            ok: false,
            stage: "precheck",
            reason: `서버가 원자적 덮어쓰기 이동(posix-rename)을 지원하지 않아 대상(${toResolved})을 안전하게 덮어쓸 수 없다.`,
          };
        }
      } else {
        try {
          await this.client.posixRename(fromResolved, toResolved);
        } catch {
          await this.client.rename(fromResolved, toResolved);
        }
      }
      // 이동 결과 확인
      const from = await this.#tryRealPath(fromResolved);
      const to = await this.#tryRealPath(toResolved);
      if (from || !to) {
        return {
          ok: false,
          stage: "verify",
          reason: `이동 검증 실패: 원본 ${from ? "아직 존재" : "사라짐"} / 대상 ${to ? "존재" : "없음"} — 원격 상태를 확인할 것.`,
        };
      }
      return { ok: true, to: to };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "move") };
    }
  }

  /**
   * chmod. 실행 비트 추가 여부를 판정해 §1 규칙(고위험과 동등)을 적용할 수 있게 한다.
   * @param {string} resolvedPath @param {number} mode
   */
  async chmod(resolvedPath, mode) {
    const conn = await this.ensureConnected();
    if (!conn.ok) return { ok: false, reason: `SFTP 연결 실패: ${conn.error}` };
    try {
      const before = await this.client.stat(resolvedPath).catch(() => null);
      const beforeMode = normalizeMode(before?.mode);
      await this.client.chmod(resolvedPath, mode);
      const after = await this.client.stat(resolvedPath).catch(() => null);
      const afterMode = normalizeMode(after?.mode);
      return {
        ok: true,
        beforeMode,
        afterMode,
        addsExecuteBit: Boolean(afterMode !== null && (afterMode & 0o111) !== 0 && (beforeMode === null || (beforeMode & 0o111) === 0)),
      };
    } catch (err) {
      return { ok: false, reason: this.#explain(err, "chmod") };
    }
  }

  /** 진단/테스트용: jail 루트의 두 경로가 실제로 보이는지 + 쓰기 가능 여부(상한 1회 호출). */
  async probeWrite(resolvedDir, mode) {
    const name = `.__sftp_guard_probe_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    const target = `${resolvedDir === "/" ? "" : resolvedDir}/${name}`;
    const content = Buffer.from(`sftp-guard write probe ${new Date().toISOString()}\n`, "utf8");
    const write = await this.writeNewFile(target, content, mode);
    if (!write.ok) return { ok: false, target, stage: write.stage, reason: write.reason };
    const del = await this.deleteFile(target);
    return { ok: del.ok, target, cleanedUp: del.ok, reason: del.ok ? undefined : `쓰기는 성공했으나 정리(삭제) 실패: ${del.reason}` };
  }

  #explain(err, op) {
    const raw = safeErrorMessage(err);
    const code = String(err?.code ?? "");
    const hint = ERROR_HINTS[code];
    const sftpNoEnt = /No such file/i.test(raw);
    const denied = code === "EACCES" || code === "EPERM" || /Permission denied|denied/i.test(raw);
    if (sftpNoEnt) return `${op}: 원격 경로 없음 (${raw})`;
    if (denied) return `${op}: 권한 거부 — ${hint ?? ERROR_HINTS.EACCES} (원본 오류: ${raw})`;
    return `${op}: ${raw}${hint ? ` — ${hint}` : ""}`;
  }
}

function normalizeMode(mode) {
  if (mode === undefined || mode === null) return null;
  if (typeof mode === "number") return mode;
  const parsed = parseInt(String(mode).replace(/[^0-7]/g, ""), 8);
  return Number.isFinite(parsed) ? parsed : null;
}

function enrichConnectError(err, connection) {
  const code = String(err?.code ?? "");
  const msg = safeErrorMessage(err);
  const where = `${connection.host}:${connection.port}`;
  const hints = {
    ECONNREFUSED: ERROR_HINTS.ECONNREFUSED,
    ETIMEDOUT: ERROR_HINTS.ETIMEDOUT,
    ENOTFOUND: ERROR_HINTS.ENOTFOUND,
    EHOSTUNREACH: ERROR_HINTS.EHOSTUNREACH,
    EACCES: ERROR_HINTS.EACCES,
  };
  const hint = hints[code] ?? "";
  const authHint = /All configured authentication methods failed|Handshake failed|encrypted packet|Unable to negotiate/i.test(msg)
    ? "인증/협상 실패 — 비밀 파일의 계정·비밀번호, sshd의 PasswordAuthentication 설정 확인."
    : "";
  const wrapped = new Error(`SFTP 연결 실패 (${where}) [${code || "no-code"}]: ${msg}${hint || authHint ? ` — ${hint || authHint}` : ""}`);
  wrapped.code = code || "SFTP_CONNECT";
  return wrapped;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export { looksBinary };
