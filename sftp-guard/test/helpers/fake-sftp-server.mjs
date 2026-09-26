// ─────────────────────────────────────────────────────────────────────────────
// 가짜 SFTP 서버 (테스트 전용) — 이미 설치된 `ssh2` 의 서버 API 로 실제 SFTP 프로토콜을 구현한다.
//
// ⚠ jail(경로 가드) 설계에 대한 중요한 메모 ────────────────────────────────────
//   ssh2 의 서버 측 SFTP 구현은 내부 디스패치 테이블(SERVER_HANDLERS)이 모듈 비공개이며
//   chroot/root 옵션이 존재하지 않는다( ssh2@1.17.0 의 lib/protocol/SFTP.js 를 직접 읽어 확인 ).
//   즉 "가짜 서버가 chroot 해 준다" 는 가정을 할 수 없다.
//   따라서 이 헬퍼는 **실제 파일시스템을 그대로 노출하는 패스스루 서버**로 구현하고,
//   경로 이탈 차단(jail)은 오직 `lib/core/remote.mjs` 의 `resolveTarget()`
//   (guardPath 어휘론적 검사 → realpath 해석 → whichRoot 재검사) 가 담당하게 한다.
//   그래야 §7 심볼릭 링크 우회 차단이 실제로 "테스트 되는 층" 에서 검증된다.
//   (서버가 미리 차단해 버리면 클라이언트 가드가 동작하는지 알 수 없다.)
//
//   읽기 계열(REALPATH/STAT/READ 등)은 루트 밖 경로도 그대로 해석해 돌려준다 — 이것이
//   심볼릭 링크 탈출 테스트가 의미 있으려면 반드시 필요한 조건이다.
//   쓰기 계열(OPEN-write/WRITE/MKDIR/RMDIR/REMOVE/RENAME/SETSTAT)만 rootDir 안으로
//   제한한다(테스트가 실수로 시스템 파일을 망가뜨리지 않도록 하는 안전장치. §7 대상 계층이 아니다).
//
//   op 통계는 `SFTP.prototype` 몽키패치가 아니라 **서버 핸들러가 emit 하는 op 이름**
//   (`sftp.emit('OPEN', reqid, filename, flags, attrs)` 등)으로 센다.
//   근거: 서버 디스패치는 모듈 비공개 SERVER_HANDLERS 가 하고, prototype 의
//   open/write/remove/... 메서드는 전부 client 전용이라 서버 모드에서 throw 한다
//   (그리고 ssh2 에는 `remove`/`posixRename` 이 없고 `unlink`/`ext_openssh_rename` 이 있다).
// ─────────────────────────────────────────────────────────────────────────────
import { generateKeyPairSync } from "node:crypto";
import { createRequire } from "node:module";
import fsp from "node:fs/promises";
import path from "node:path";

// ── ssh2 로더 ────────────────────────────────────────────────────────────────
let cachedSsh2 = null;

/**
 * 이미 설치된 ssh2 를 ESM 으로 로드한다.
 * ssh2 는 CJS 라 cjs-module-lexer 가 `Server` named export 를 뽑지 못할 수 있다
 * (실측: `import("ssh2")` 의 키는 AgentProtocol/BaseAgent/Client/createAgent/default 뿐).
 * 그래서 named export 를 못 보면 `default` 로 접근하고, 그것도 실패하면
 * createRequire(import.meta.url) 로 CJS 를 직접 요구한다.
 */
export async function loadSsh2() {
  if (cachedSsh2) return cachedSsh2;
  try {
    const mod = await import("ssh2");
    const lib = typeof mod?.Server === "function" ? mod : (mod?.default ?? {});
    if (typeof lib.Server === "function") {
      cachedSsh2 = lib;
      return cachedSsh2;
    }
  } catch {
    /* 평면 import 실패 → require 폴백 */
  }
  const requireCjs = createRequire(import.meta.url);
  cachedSsh2 = requireCjs("ssh2");
  if (typeof cachedSsh2.Server !== "function") throw new Error("ssh2 의 Server API 를 찾지 못했습니다");
  return cachedSsh2;
}

// ── SFTP 프로토콜 상수(ssh2 의 utils.sftp 에서 가져온다) ──────────────────────
// 모듈 최상위 await 를 쓰면 "의존성 미설치" 상태에서 이 파일을 import 하는 순간 터져,
// 테스트 러너가 헬퍼 파일 자체를 실패로 보고한다(테스트 실패가 아니라 도구 실패).
// 그래서 지연 초기화하고, 시작 시점에 명확히 실패시킨다.
let SFTP_PROTO = null;
try {
  SFTP_PROTO = await loadSsh2().then((l) => l.utils.sftp);
} catch {
  SFTP_PROTO = null; // 의존성 없음 — start() 가 명확히 알린다
}
const STATUS_CODE = SFTP_PROTO?.STATUS_CODE ?? {};
const OPEN_MODE = SFTP_PROTO?.OPEN_MODE ?? {};
const RESPONSE_VERSION = 2;

/** 모든 op 카운터를 0 으로 초기화한 통계 객체(호출자가 라이브로 읽는다). */
function newStats() {
  return {
    // 요청(요청 이름) — 릴리스 사양에 나열된 키를 모두 포함한다.
    open: 0,
    close: 0,
    read: 0,
    write: 0,
    remove: 0,
    rename: 0,
    posixRename: 0,
    mkdir: 0,
    rmdir: 0,
    setstat: 0,
    fsetstat: 0,
    realpath: 0,
    opendir: 0,
    readdir: 0,
    stat: 0,
    lstat: 0,
    fstat: 0,
    readlink: 0,
    symlink: 0,
    // 누적 바이트/연결 지표
    bytesWritten: 0,
    bytesRead: 0,
    sessions: 0,
    connections: 0,
    drops: 0,
    errors: 0,
    faults: {},
  };
}

/**
 * 가짜 SFTP 서버를 기동한다.
 * @param {{rootDir: string, port?: number, username?: string, password?: string,
 *          advertisePosixRename?: boolean, jailWrites?: boolean}} opts
 * @returns {Promise<{host: string, port: number, rootDir: string, stats: object,
 *                    stop: () => Promise<void>, dropAfterBytes: (n: number|null) => void,
 *                    disablePosixRename: () => void, enablePosixRename: () => void,
 *                    posixRenameAdvertised: () => boolean, dropConnection: () => void,
 *                    seed: (relPath: string, content: Buffer|string) => Promise<string>}>}
 */
export async function startFakeSftpServer(opts = {}) {
  if (!SFTP_PROTO) {
    throw new Error(
      "ssh2 가 설치되어 있지 않습니다. 이 통합 테스트는 실제 SFTP 서버를 띄우므로 `npm install` 후 실행하세요.",
    );
  }
  const rootDir = path.resolve(opts.rootDir ?? process.cwd());
  const username = opts.username ?? "sftp-test-user";
  const password = opts.password ?? "test-pass";
  const host = "127.0.0.1";
  const stats = newStats();

  /** 쓰기 계열만 루트 안으로 제한(안전장치). §7 대상 계층이 아니다. */
  const jailWrites = opts.jailWrites !== false;
  let posixRenameSupported = opts.advertisePosixRename !== false;
  /** VERSION 패킷 확장 광고 후킹이 실제로 먹혔는지. */
  let extensionsAdvertised = false;

  const { Server } = await loadSsh2();

  // ── 호스트 키: 프로세스 안에서만 존재(디스크에 쓰지 않는다) ─────────────────
  // eslint-disable-next-line no-undef
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  /** 소켓 단절 상태(하강 조작 상태) */
  const state = {
    dropAfter: null, // null 이면 비활성
    clients: new Set(),
  };

  const server = new Server({ hostKeys: [privateKey], debug: opts.debug ? (m) => opts.debug(m) : undefined }, (client) => {
    stats.connections++;
    state.clients.add(client);
    client.on("close", () => state.clients.delete(client));
    // 소켓/프로토콜 오류: 조용히 삼킨다(테스트를 죽이지 않기 위해). debug 옵션 켜면 원인을 찍는다.
    client.on("error", (e) => {
      stats.errors++;
      if (opts.debug) console.error("[SRV client error]", e && e.stack ? e.stack : e);
    });

    // ── 인증: password 만, 정확히 일치할 때만 ────────────────────────────────
    // 주의: ssh2 클라이언트는 "none" 요청을 먼저 보낸다. 여기서 reject() 를 인자 없이 부르면
    // USERAUTH_FAILURE 의 "남은 방법 목록" 이 빈 문자열이 되어 클라이언트가 즉시
    // "All configured authentication methods failed" 로 포기한다(실측).
    // 그래서 실제 sshd 처럼 남은 방법("password") 을 명시한다.
    client.on("authentication", (ctx) => {
      if (ctx.method === "password" && ctx.username === username && String(ctx.password) === password) {
        ctx.accept();
        return;
      }
      ctx.reject(["password"]);
    });

    client.on("ready", () => {
      // ── 세션: "sftp" 서브시스템만 허용 ─────────────────────────────────────
      client.on("session", (acceptSession) => {
        const session = acceptSession();
        session.on("sftp", (acceptSftp) => {
          const sftp = acceptSftp();
          stats.sessions++;
          extensionsAdvertised = advertiseExtensions(sftp);
          installHandlers({ sftp, stats, state, rootDir, jailWrites, isPosixRenameEnabled: () => posixRenameSupported });
        });
        session.on("subsystem", (_accept, reject) => {
          if (reject) reject();
        });
        session.on("env", (accept) => accept && accept());
        session.on("pty", (accept) => accept && accept());
        session.on("window-change", (accept) => accept && accept());
        session.on("exec", (_accept, reject) => {
          if (reject) reject();
        });
        session.on("shell", (_accept, reject) => {
          if (reject) reject();
        });
      });
    });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const port = server.address().port;

  return {
    host,
    port,
    rootDir,
    stats,
    username,
    password,
    /** N 바이트를 WRITE 로 받았으면 그 다음 순간 연결을 끊는다(중간 전송 끊김 재현). null 이면 해제. */
    dropAfterBytes(n) {
      state.dropAfter = n === null || n === undefined ? null : Number(n);
    },
    /** 서버가 posix-rename 확장을 광고했는지(=클라이언트가 ext_openssh_rename 을 쓸 수 있는지). */
    posixRenameAdvertised() {
      return posixRenameSupported && extensionsAdvertised;
    },
    disablePosixRename() {
      posixRenameSupported = false;
    },
    enablePosixRename() {
      posixRenameSupported = true;
    },
    /** 지금 즉시 모든 연결을 끊는다(중간 전송 끊김). */
    dropConnection() {
      for (const c of state.clients) {
        try {
          if (c._sock && typeof c._sock.destroy === "function") c._sock.destroy();
          else if (typeof c.end === "function") c.end();
        } catch {
          /* 이미 닫혔음 */
        }
      }
    },
    /** 테스트 픽스처용: rootDir 아래에 파일을 심는다. */
    async seed(relPath, content) {
      const target = path.join(rootDir, relPath);
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await fsp.writeFile(target, content);
      return target;
    },
    async stop() {
      try {
        state.clients.forEach((c) => {
          try {
            if (typeof c.end === "function") c.end();
          } catch {
            /* noop */
          }
        });
        state.clients.clear();
      } catch {
        /* noop */
      }
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// VERSION 패킷 확장 광고
// ─────────────────────────────────────────────────────────────────────────────
// ssh2 의 서버는 클라이언트 INITIALIZING 을 받으면 모듈 고정 SERVER_VERSION_BUFFER
// (길이 4 + type 1 + version 4 = 9바이트, 확장 목록 없음)를 그대로 보낸다.
// 확장 미광고 상태에서는 ssh2 클라이언트의 `ext_openssh_rename()` 이
// "Server does not support this extended request" 로 동기 throw 하므로
// posix-rename 분기(원자적 덮어쓰기)를 테스트할 수 없다.
// 그래서 첫 VERSION 패킷을 확장 항목을 붙인 것으로 교체한다(테스트 헬퍼 내부 전용 후킹).
const patchedProtocols = new WeakSet();

function sftpString(s) {
  const body = Buffer.from(s, "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length, 0);
  return Buffer.concat([head, body]);
}

function buildVersionPacket() {
  // SFTP VERSION 패킷: length(4) | type(1)=2 | version(4)=3 | 확장들
  // (길이 필드가 전체-1 이므로 반드시 정확히 맞춰야 한다 — 어긋나면 클라이언트가 "Unknown packet type" 로 죽는다)
  const body = Buffer.concat([Buffer.from([RESPONSE_VERSION, 0, 0, 0, 3]), sftpString("posix-rename@openssh.com"), sftpString("1")]);
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length, 0);
  return Buffer.concat([head, body]);
}

function advertiseExtensions(sftp) {
  const proto = sftp?._protocol;
  if (!proto || typeof proto.channelData !== "function") return false;
  if (patchedProtocols.has(proto)) return true;
  patchedProtocols.add(proto);
  const orig = proto.channelData.bind(proto);
  let done = false;
  proto.channelData = (id, data) => {
    // SERVER_VERSION_BUFFER = [len(4) | type(1) | version(4)] = 9 바이트
    if (!done && Buffer.isBuffer(data) && data.length === 9 && data[4] === RESPONSE_VERSION) {
      done = true;
      data = buildVersionPacket();
    }
    return orig(id, data);
  };
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// SFTP op 핸들러
// ─────────────────────────────────────────────────────────────────────────────
function installHandlers({ sftp, stats, state, rootDir, jailWrites, isPosixRenameEnabled }) {
  /** 열려 있는 핸들 → 파일 핸들 / 디렉터리 스냅샷 */
  const handles = new Map();
  let nextHandle = 1;

  const makeHandle = () => {
    const id = nextHandle++;
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(id, 0);
    handles.set(id, { kind: "file", fh: null, path: null });
    return buf;
  };
  const takeHandle = (handle) => {
    if (!Buffer.isBuffer(handle) || handle.length !== 4) return null;
    return handles.get(handle.readUInt32BE(0)) ?? null;
  };

  const ok = (reqid) => sftp.status(reqid, STATUS_CODE.OK);
  const fail = (reqid, code) => sftp.status(reqid, code);

  /** node fs 오류 → SFTP status 코드 매핑 */
  const statusFor = (err) => {
    switch (err?.code) {
      case "ENOENT":
        return STATUS_CODE.NO_SUCH_FILE;
      case "EACCES":
      case "EPERM":
        return STATUS_CODE.PERMISSION_DENIED;
      case "EISDIR":
      case "ENOTDIR":
      case "ENOTEMPTY":
      case "EEXIST":
      case "EXDEV":
      case "ELOOP":
        return STATUS_CODE.FAILURE;
      default:
        return STATUS_CODE.FAILURE;
    }
  };
  const countFault = (code) => {
    stats.faults[code] = (stats.faults[code] ?? 0) + 1;
  };

  /** 쓰기 계열 jail: rootDir 밖이면 거부(테스트 안전장치) */
  const writeJailOk = (p) => {
    if (!jailWrites) return true;
    const rel = path.relative(rootDir, path.resolve(p));
    return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
  };

  const attrsOf = (st) => ({
    mode: st.mode,
    uid: st.uid,
    gid: st.gid,
    size: st.size,
    atime: Math.floor(st.atimeMs / 1000),
    mtime: Math.floor(st.mtimeMs / 1000),
  });

  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const rwx = (m) => `${m & 4 ? "r" : "-"}${m & 2 ? "w" : "-"}${m & 1 ? "x" : "-"}`;
  const longname = (name, st) => {
    const fmt = (st.mode & 0o170000) === 0o040000 ? "d" : (st.mode & 0o170000) === 0o120000 ? "l" : "-";
    const perm = rwx((st.mode >> 6) & 7) + rwx((st.mode >> 3) & 7) + rwx(st.mode & 7);
    const d = new Date(st.mtimeMs);
    const day = String(d.getDate()).padStart(2, " ");
    const hhmm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    return `${fmt}${perm} 1 ${st.uid} ${st.gid} ${st.size} ${MONTHS[d.getMonth()]} ${day} ${hhmm} ${name}`;
  };

  // ── REALPATH ──────────────────────────────────────────────────────────────
  sftp.on("REALPATH", (reqid, p) => {
    stats.realpath++;
    void (async () => {
      try {
        const abs = p === "." || p === "" ? rootDir : path.resolve(rootDir, p);
        const resolved = await fsp.realpath(abs);
        sftp.name(reqid, [{ filename: resolved, longname: resolved, attrs: {} }]);
      } catch (err) {
        countFault(err?.code ?? "REALPATH");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── STAT / LSTAT ──────────────────────────────────────────────────────────
  const onStat = (key) => (reqid, p) => {
    stats[key]++;
    void (async () => {
      try {
        const st = await fsp[key === "stat" ? "stat" : "lstat"](path.resolve(rootDir, p));
        sftp.attrs(reqid, attrsOf(st));
      } catch (err) {
        countFault(err?.code ?? key);
        fail(reqid, statusFor(err));
      }
    })();
  };
  sftp.on("STAT", onStat("stat"));
  sftp.on("LSTAT", onStat("lstat"));

  // ── OPEN ──────────────────────────────────────────────────────────────────
  sftp.on("OPEN", (reqid, filename, flags, attrs) => {
    stats.open++;
    void (async () => {
      const abs = path.resolve(rootDir, filename);
      if (!writeJailOk(abs)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      const read = Boolean(flags & OPEN_MODE.READ);
      const write = Boolean(flags & OPEN_MODE.WRITE);
      const creat = Boolean(flags & OPEN_MODE.CREAT);
      const excl = Boolean(flags & OPEN_MODE.EXCL);
      const trunc = Boolean(flags & OPEN_MODE.TRUNC);
      const append = Boolean(flags & OPEN_MODE.APPEND);
      let nodeFlag;
      if (write && creat && excl) nodeFlag = "wx";
      else if (write && creat && trunc) nodeFlag = "w";
      else if (write && creat) nodeFlag = "w";
      else if (write && append) nodeFlag = "a";
      else if (write && read) nodeFlag = "r+";
      else if (write) nodeFlag = "r+";
      else nodeFlag = "r";
      if (!write && !read) return fail(reqid, STATUS_CODE.FAILURE);
      const mode = typeof attrs?.mode === "number" && attrs.mode > 0 ? attrs.mode & 0o7777 : 0o666;
      try {
        const fh = await fsp.open(abs, nodeFlag, mode);
        const h = makeHandle();
        const rec = takeHandle(h);
        rec.kind = "file";
        rec.fh = fh;
        rec.path = abs;
        rec.append = append;
        sftp.handle(reqid, h);
      } catch (err) {
        countFault(err?.code ?? "OPEN");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── CLOSE ─────────────────────────────────────────────────────────────────
  sftp.on("CLOSE", (reqid, handle) => {
    stats.close++;
    const rec = takeHandle(handle);
    if (!rec) return fail(reqid, STATUS_CODE.FAILURE);
    handles.delete(handle.readUInt32BE(0));
    if (rec.fh) {
      rec.fh.close().then(
        () => ok(reqid),
        () => ok(reqid),
      );
      return;
    }
    ok(reqid);
  });

  // ── READ ──────────────────────────────────────────────────────────────────
  sftp.on("READ", (reqid, handle, offset, length) => {
    stats.read++;
    const rec = takeHandle(handle);
    if (!rec || rec.kind !== "file") return fail(reqid, STATUS_CODE.FAILURE);
    void (async () => {
      try {
        const st = await rec.fh.stat();
        if (offset >= st.size) return fail(reqid, STATUS_CODE.EOF);
        const want = Math.min(length, st.size - offset);
        const buf = Buffer.allocUnsafe(want);
        const { bytesRead } = await rec.fh.read(buf, 0, want, offset);
        stats.bytesRead += bytesRead;
        sftp.data(reqid, buf.subarray(0, bytesRead));
      } catch (err) {
        countFault(err?.code ?? "READ");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── WRITE (+ 중간 전송 끊김 주입 지점) ────────────────────────────────────
  sftp.on("WRITE", (reqid, handle, offset, data) => {
    stats.write++;
    stats.bytesWritten += data.length;
    const rec = takeHandle(handle);
    if (!rec || rec.kind !== "file") return fail(reqid, STATUS_CODE.FAILURE);
    // 하강 조작: N 바이트 누적 뒤 연결을 끊는다("network drop mid-write").
    if (state.dropAfter !== null && stats.bytesWritten >= state.dropAfter) {
      stats.drops++;
      state.dropAfter = null;
      void (async () => {
        try {
          await rec.fh.close();
        } catch {
          /* noop */
        }
        for (const c of state.clients) {
          try {
            if (c._sock && typeof c._sock.destroy === "function") c._sock.destroy();
            else if (typeof c.end === "function") c.end();
          } catch {
            /* noop */
          }
        }
      })();
      return; // 응답 없이 끊는다 → 클라이언트는 "No response from server" 로 실패해야 한다
    }
    void (async () => {
      try {
        await rec.fh.write(data, 0, data.length, offset);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "WRITE");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── FSTAT ─────────────────────────────────────────────────────────────────
  sftp.on("FSTAT", (reqid, handle) => {
    stats.fstat++;
    const rec = takeHandle(handle);
    if (!rec || rec.kind !== "file") return fail(reqid, STATUS_CODE.FAILURE);
    void (async () => {
      try {
        sftp.attrs(reqid, attrsOf(await rec.fh.stat()));
      } catch (err) {
        countFault(err?.code ?? "FSTAT");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── OPENDIR / READDIR ─────────────────────────────────────────────────────
  sftp.on("OPENDIR", (reqid, p) => {
    stats.opendir++;
    void (async () => {
      try {
        const abs = path.resolve(rootDir, p);
        const dirents = await fsp.readdir(abs, { withFileTypes: true });
        const entries = [];
        for (const d of dirents) {
          const st = await fsp.lstat(path.join(abs, d.name));
          entries.push({ name: d.name, st, longname: longname(d.name, st) });
        }
        const h = makeHandle();
        const rec = takeHandle(h);
        rec.kind = "dir";
        rec.entries = entries;
        rec.index = 0;
        sftp.handle(reqid, h);
      } catch (err) {
        countFault(err?.code ?? "OPENDIR");
        fail(reqid, statusFor(err));
      }
    })();
  });

  const BATCH = 64;
  sftp.on("READDIR", (reqid, handle) => {
    stats.readdir++;
    const rec = takeHandle(handle);
    if (!rec || rec.kind !== "dir") return fail(reqid, STATUS_CODE.FAILURE);
    const batch = rec.entries.slice(rec.index, rec.index + BATCH);
    rec.index += batch.length;
    if (batch.length === 0) return fail(reqid, STATUS_CODE.EOF);
    sftp.name(
      reqid,
      batch.map((e) => ({ filename: e.name, longname: e.longname, attrs: attrsOf(e.st) })),
    );
  });

  // ── REMOVE(unlink) / RMDIR ────────────────────────────────────────────────
  sftp.on("REMOVE", (reqid, p) => {
    stats.remove++;
    void (async () => {
      const abs = path.resolve(rootDir, p);
      if (!writeJailOk(abs)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      try {
        await fsp.unlink(abs); // 디렉터리에선 EISDIR/EPERM → FAILURE(재귀 삭제 아님)
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "REMOVE");
        fail(reqid, statusFor(err));
      }
    })();
  });

  sftp.on("RMDIR", (reqid, p) => {
    stats.rmdir++;
    void (async () => {
      const abs = path.resolve(rootDir, p);
      if (!writeJailOk(abs)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      try {
        await fsp.rmdir(abs);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "RMDIR");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── MKDIR ─────────────────────────────────────────────────────────────────
  sftp.on("MKDIR", (reqid, p, attrs) => {
    stats.mkdir++;
    void (async () => {
      const abs = path.resolve(rootDir, p);
      if (!writeJailOk(abs)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      const mode = typeof attrs?.mode === "number" && attrs.mode > 0 ? attrs.mode & 0o7777 : 0o777;
      try {
        await fsp.mkdir(abs, mode);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "MKDIR");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── RENAME (SSH_FXP_RENAME: 대상이 있으면 실패 — OpenSSH 와 동일) ────────
  sftp.on("RENAME", (reqid, from, to) => {
    stats.rename++;
    void (async () => {
      const a = path.resolve(rootDir, from);
      const b = path.resolve(rootDir, to);
      if (!writeJailOk(a) || !writeJailOk(b)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      try {
        await fsp.access(b);
        return fail(reqid, STATUS_CODE.FAILURE); // OpenSSH: 존재하는 대상으로의 RENAME 은 실패
      } catch {
        /* 대상 없음 → 진행 */
      }
      try {
        await fsp.rename(a, b);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "RENAME");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── SETSTAT / FSETSTAT ────────────────────────────────────────────────────
  const applyAttrs = async (target, attrs, handle) => {
    if (typeof attrs?.mode === "number") {
      if (handle) await handle.chmod(attrs.mode & 0o7777);
      else await fsp.chmod(target, attrs.mode & 0o7777);
    }
    if (typeof attrs?.uid === "number" || typeof attrs?.gid === "number") {
      const st = await fsp.stat(target);
      const uid = typeof attrs.uid === "number" ? attrs.uid : st.uid;
      const gid = typeof attrs.gid === "number" ? attrs.gid : st.gid;
      await fsp.chown(target, uid, gid);
    }
    if (typeof attrs?.size === "number") {
      if (handle) await handle.truncate(attrs.size);
      else await fsp.truncate(target, attrs.size);
    }
    if (typeof attrs?.atime === "number" || typeof attrs?.mtime === "number") {
      const st = await fsp.stat(target);
      const at = typeof attrs.atime === "number" ? attrs.atime : Math.floor(st.atimeMs / 1000);
      const mt = typeof attrs.mtime === "number" ? attrs.mtime : Math.floor(st.mtimeMs / 1000);
      await fsp.utimes(target, at, mt);
    }
  };

  sftp.on("SETSTAT", (reqid, p, attrs) => {
    stats.setstat++;
    void (async () => {
      const abs = path.resolve(rootDir, p);
      if (!writeJailOk(abs)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      try {
        await applyAttrs(abs, attrs, null);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "SETSTAT");
        fail(reqid, statusFor(err));
      }
    })();
  });

  sftp.on("FSETSTAT", (reqid, handle, attrs) => {
    stats.fsetstat++;
    const rec = takeHandle(handle);
    if (!rec || rec.kind !== "file") return fail(reqid, STATUS_CODE.FAILURE);
    void (async () => {
      try {
        await applyAttrs(rec.path, attrs, rec.fh);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "FSETSTAT");
        // ssh2 WriteStream 은 fchmod 실패를 무시하고 진행한다(그래서 ok 로 닫지 않고 실패를 알린다).
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── READLINK / SYMLINK ────────────────────────────────────────────────────
  sftp.on("READLINK", (reqid, p) => {
    stats.readlink++;
    void (async () => {
      try {
        const target = await fsp.readlink(path.resolve(rootDir, p));
        sftp.name(reqid, [{ filename: target, longname: target, attrs: {} }]);
      } catch (err) {
        countFault(err?.code ?? "READLINK");
        fail(reqid, statusFor(err));
      }
    })();
  });

  sftp.on("SYMLINK", (reqid, target, linkPath) => {
    stats.symlink++;
    void (async () => {
      const abs = path.resolve(rootDir, linkPath);
      if (!writeJailOk(abs)) {
        countFault("EACCES_WRITE_JAIL");
        return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
      }
      try {
        await fsp.symlink(target, abs);
        ok(reqid);
      } catch (err) {
        countFault(err?.code ?? "SYMLINK");
        fail(reqid, statusFor(err));
      }
    })();
  });

  // ── EXTENDED (posix-rename@openssh.com) ───────────────────────────────────
  sftp.on("EXTENDED", (reqid, extName, data) => {
    if (extName === "posix-rename@openssh.com") {
      stats.posixRename++;
      if (!isPosixRenameEnabled()) return fail(reqid, STATUS_CODE.OP_UNSUPPORTED);
      void (async () => {
        const [from, to] = parseTwoStrings(data);
        if (from === null || to === null) return fail(reqid, STATUS_CODE.FAILURE);
        const a = path.resolve(rootDir, from);
        const b = path.resolve(rootDir, to);
        if (!writeJailOk(a) || !writeJailOk(b)) {
          countFault("EACCES_WRITE_JAIL");
          return fail(reqid, STATUS_CODE.PERMISSION_DENIED);
        }
        try {
          await fsp.rename(a, b); // POSIX rename: 대상이 있어도 원자적으로 덮어쓴다
          ok(reqid);
        } catch (err) {
          countFault(err?.code ?? "POSIX_RENAME");
          fail(reqid, statusFor(err));
        }
      })();
      return;
    }
    fail(reqid, STATUS_CODE.OP_UNSUPPORTED);
  });

  sftp.on("error", () => {
    /* 프로토콜 오류는 통째로 무시(테스트를 죽이지 않는다) */
  });
}

/** EXTENDED 페이로드에서 두 개의 SFTP 문자열(경로)을 꺼낸다. */
function parseTwoStrings(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 8) return [null, null];
  const out = [];
  let p = 0;
  for (let i = 0; i < 2; i++) {
    const len = buf.readUInt32BE(p);
    p += 4;
    if (p + len > buf.length) return [null, null];
    out.push(buf.subarray(p, p + len).toString("utf8"));
    p += len;
  }
  return out;
}
