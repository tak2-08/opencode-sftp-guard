// 실제 SFTP 통합 테스트 — 가짜 ssh2 서버(테스트 헬퍼) ↔ lib/core/remote.mjs 의 SftpTransport.
// 대상 계층: 경로 해석/가드(§7), 쓰기 무결성 검증, 동시성 제어, 삭제/이동/권한 변경, 경로 잠금.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SftpTransport } from "../lib/core/remote.mjs";
import { sha256 } from "../lib/core/util.mjs";

const T = { timeout: 30000 };

/**
 * 의존성(`ssh2-sftp-client`, `ssh2`)이 없으면 "실패" 가 아니라 "건너뜀" 으로 처리한다.
 * 이유는 공개 저장소에서 `npm install` 없이 바로 `node --test` 를 돌리는 사람이 많기 때문이며,
 * 실패로 보이면 "내 코드가 깨졌다" 는 오해를 만든다. 통합 테스트의 실행 방법은:
 *   cd <repo> && npm install && npm test
 */
let DEPENDENCY_ERROR = null;
try {
  await import("ssh2-sftp-client");
} catch (err) {
  DEPENDENCY_ERROR = err;
}

/** 헬퍼는 모듈 최상위 await 로 ssh2 를 요구하므로 의존성이 있을 때만 동적으로 불러온다. */
let startFakeSftpServer = null;
if (!DEPENDENCY_ERROR) {
  ({ startFakeSftpServer } = await import("./helpers/fake-sftp-server.mjs"));
}

/** 루트 계정이면 권한 거부 테스트를 의미 있게 돌릴 수 없다. */
const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

describe("integration — SftpTransport ↔ 실제 SFTP 서버", { skip: DEPENDENCY_ERROR ? "의존성 미설치 — cd <repo> && npm install 후 다시 실행" : false }, () => {
  let base;
  let rootDir; // 허용 루트(jail 안쪽)
  let outsideDir; // 허용 루트 밖(탈출 검출용)
  let server;
  let transport;
  const events = [];

  /** 테스트마다 다른 하위 디렉터리를 만들어 서로 간섭을 막는다. */
  let seq = 0;
  const sub = (name) => {
    const dir = join(rootDir, `t${String(++seq).padStart(2, "0")}-${name}`);
    mkdirSync(dir, { recursive: true });
    return dir;
  };
  const rpath = (...parts) => join(rootDir, ...parts);

  before(async () => {
    base = mkdtempSync(join(tmpdir(), "sftpguard-it-"));
    rootDir = join(base, "root");
    outsideDir = join(base, "outside");
    mkdirSync(rootDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    server = await startFakeSftpServer({ rootDir });
    transport = new SftpTransport({
      connection: {
        host: "127.0.0.1",
        port: server.port,
        username: "sftp-test-user",
        password: "test-pass",
        readyTimeoutMs: 10000,
        keepaliveIntervalMs: 5000,
        keepaliveCountMax: 3,
      },
      allowedRoots: [rootDir],
      connectRetries: 0,
      onEvent: (e) => events.push(e),
    });
  });

  after(async () => {
    try {
      await transport?.close();
    } catch {
      /* 이미 닫혔을 수 있다 */
    }
    await server?.stop();
    rmSync(base, { recursive: true, force: true });
  });

  /** 연결이 끊긴 뒤에는 테스트를 계속하기 위해 다시 붙는다(지연 재연결 계약). */
  const reconnect = async () => {
    await transport.close();
    const r = await transport.ensureConnected();
    assert.equal(r.ok, true, `재연결 실패: ${r.error}`);
  };

  // ─────────────────────────────────────────────────────────────────────────
  test("1) resolveTarget: 존재 파일 / 없는 경로 / `..` / 루트 밖", T, async () => {
    const dir = sub("resolve");
    const file = join(dir, "a.css");
    writeFileSync(file, "body{color:red}\n");

    const hit = await transport.resolveTarget(file);
    assert.equal(hit.ok, true, hit.reason);
    assert.equal(hit.kind, "file");
    assert.equal(hit.resolved, file);
    assert.equal(hit.root, rootDir);
    assert.ok(hit.resolved.startsWith(`${rootDir}/`), "해결된 경로는 허용 루트 아래여야 한다");
    assert.equal(hit.attrs.isFile, true);

    const missing = await transport.resolveTarget(join(dir, "new.css"));
    assert.equal(missing.ok, true, missing.reason);
    assert.equal(missing.kind, "absent", "아직 없는 파일은 absent 로 분류되어야 한다");

    const mustExist = await transport.resolveTarget(join(dir, "new.css"), { mustExist: true });
    assert.equal(mustExist.ok, false);
    assert.match(mustExist.reason, /존재하지 않음/);

    const dirHit = await transport.resolveTarget(dir);
    assert.equal(dirHit.ok, true);
    assert.equal(dirHit.kind, "directory");

    // node:path 의 join 은 `..` 를 미리 없애므로, 가드가 원본을 본도록 문자열로 직접 만든다.
    const dotted = await transport.resolveTarget(`${dir}/../../outside/secret.txt`);
    assert.equal(dotted.ok, false, "`..` 는 정규화하더라도 거부되어야 한다");
    assert.match(dotted.reason, /\.\./);

    for (const outside of ["/etc/hostname", join(outsideDir, "free.txt")]) {
      const r = await transport.resolveTarget(outside);
      assert.equal(r.ok, false, `${outside} 는 거부되어야 한다`);
      assert.match(r.reason, /허용 루트 밖/);
      assert.ok(r.reason.includes(rootDir), "거부 이유에 허용 루트 목록이 보여야 한다");
    }
  });

  test("1b) resolveTarget: scopePaths 로 범위 판정을 함께 계산한다", T, async () => {
    const dir = sub("scope");
    const inScopeFile = join(dir, "in.css");
    const outScopeFile = join(dir, "out.css");
    writeFileSync(inScopeFile, "a{}\n");
    writeFileSync(outScopeFile, "b{}\n");

    const a = await transport.resolveTarget(inScopeFile, { scopePaths: [dir] });
    assert.equal(a.ok, true);
    assert.equal(a.inScope, true);
    assert.equal(a.matched ?? a.inScope, true);

    const b = await transport.resolveTarget(outScopeFile, { scopePaths: [join(dir, "in.css")] });
    assert.equal(b.ok, true);
    assert.equal(b.inScope, false, "다른 파일 하나만 스코프면 이 파일은 범위 밖이다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("2) §7 핵심: 심볼릭 링크로 허용 루트 탈출 차단 (디렉터리/파일 모두)", T, async () => {
    const canary = "CANARY-OUTSIDE-DO-NOT-READ-8f3a";
    writeFileSync(join(outsideDir, "secret.txt"), `${canary}\n`);
    const dir = sub("symlink");
    symlinkSync(outsideDir, join(dir, "link-dir"));
    symlinkSync(join(outsideDir, "secret.txt"), join(dir, "link-file.txt"));

    for (const [label, target] of [
      ["디렉터리 심볼릭 링크", join(dir, "link-dir", "secret.txt")],
      ["파일 심볼릭 링크", join(dir, "link-file.txt")],
    ]) {
      const r = await transport.resolveTarget(target);
      assert.equal(r.ok, false, `${label} 를 통한 탈출은 막혀야 한다`);
      assert.match(r.reason, /심볼릭 링크/, `${label}: 거부 이유에 심볼릭 링크 언급이 있어야 한다`);
      assert.ok(r.resolved.startsWith(outsideDir), "서버는 실제 파일시스템을 그대로 보여준다(탈출은 클라이언트 가드가 막음)");
      // 파일 본문은 읽히지 않았어야 한다(모델/트랜스크립트로 새면 안 된다).
      assert.equal(r.buffer, undefined);
      assert.equal(r.content, undefined);
      assert.ok(!JSON.stringify(r).includes(canary), `${label}: 루트 밖 파일 본문이 결과에 포함되면 안 된다`);
    }

    // 탈출 경로로 실제 읽기를 시도해도 resolveTarget 을 우회할 수 없다.
    const escape = await transport.resolveTarget(join(dir, "link-dir", "secret.txt"));
    assert.equal(escape.ok, false);
    assert.ok(!JSON.stringify(escape).includes(canary));
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("3) writeNewFile: 바이트 단위 일치 + sha256 일치 + `wx` no-clobber", T, async () => {
    const dir = sub("write-new");
    const target = join(dir, "note.txt");
    const content = Buffer.from("첫 줄\n둘째 줄\n\u0000 binary-ish \n", "utf8");

    const w = await transport.writeNewFile(target, content, 0o644);
    assert.equal(w.ok, true, w.reason);
    assert.equal(w.sha256, sha256(content));
    assert.equal(w.size, content.length);
    assert.equal(readFileSync(target).equals(content), true, "원격 내용이 바이트 단위로 같아야 한다");

    // flags:"wx" — 같은 경로에 다시 쓰면 덮어쓰지 않고 실패해야 한다.
    const again = await transport.writeNewFile(target, Buffer.from("덮어쓰기 시도\n"), 0o644);
    assert.equal(again.ok, false, "이미 있는 파일을 덮어써서는 안 된다");
    assert.ok(again.reason.length > 0);
    assert.equal(readFileSync(target).equals(content), true, "실패한 두 번째 쓰기가 원본을 훼손해서는 안 된다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("4) verifyWritten: 중간 전송 끊김(200KB)을 성공으로 다루지 않는다", T, async () => {
    const dir = sub("drop");
    const target = join(dir, "big.bin");
    const payload = Buffer.alloc(200 * 1024, 0x41);
    payload[0] = 0x00;
    payload[payload.length - 1] = 0xff;

    // 누적 WRITE 바이트 기준 N 바이트 뒤에서 연결을 끊는다.
    server.dropAfterBytes(server.stats.bytesWritten + 64 * 1024);
    const w = await transport.writeNewFile(target, payload, 0o644);
    server.dropAfterBytes(null);

    assert.equal(w.ok, false, "연결이 끊겼는데 성공으로 보고하면 안 된다");
    assert.ok(typeof w.reason === "string" && w.reason.length > 0, "실패 이유가 있어야 한다");
    assert.ok(["open", "verify"].includes(w.stage), `stage 는 open/verify 여야 한다 (실제: ${w.stage})`);
    assert.equal(server.stats.drops, 1, "서버가 실제로 한 번 끊었어야 한다");

    await reconnect();
    const after = await transport.stat(target);
    if (after.ok) {
      assert.notEqual(after.attrs.size, payload.length, "조각난 파일이 전송 내용과 같다고 보고되면 안 된다");
    } else {
      assert.match(after.reason, /경로 없음|No such file/);
    }
    // 성공으로 오인된 정황이 없어야 한다.
    assert.notEqual(w.sha256, sha256(payload));
  });

  test("4b) verifyWritten: 크기가 같아도 해시가 다르면 실패로 판정한다 (결정적 검증)", T, async () => {
    const dir = sub("verify");
    const target = join(dir, "same-size.txt");
    const original = Buffer.from("0123456789");
    assert.equal((await transport.writeNewFile(target, original, 0o644)).ok, true);

    const v = await transport.verifyWritten(target, Buffer.from("9876543210"));
    assert.equal(v.ok, false, "길이가 같아도 내용이 다르면 실패여야 한다");
    assert.equal(v.stage, "verify");
    assert.match(v.reason, /해시 불일치/);

    const okVerify = await transport.verifyWritten(target, original);
    assert.equal(okVerify.ok, true, "같은 내용이면 검증을 통과해야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("5) overwriteFile: 덮어쓰기 후 재읽기 일치", T, async () => {
    const dir = sub("overwrite");
    const target = join(dir, "doc.md");
    const first = Buffer.from("# 제목\n\n본문 1\n");
    const second = Buffer.from("# 제목\n\n본문 2\n");
    await transport.writeNewFile(target, first, 0o644);

    const w = await transport.overwriteFile(target, second, 0o644, { expectedSha256: sha256(first) });
    assert.equal(w.ok, true, w.reason);
    const read = await transport.readFile(target, 1024 * 1024);
    assert.equal(read.ok, true, read.reason);
    assert.equal(read.buffer.equals(second), true);
    assert.equal(read.sha256, sha256(second));
  });

  test("5b) overwriteFile: 낡은 expectedSha256 면 stage 'concurrency' + 원본 보존", T, async () => {
    const dir = sub("concurrency");
    const target = join(dir, "shared.txt");
    const current = Buffer.from("사람이 방금 고친 내용\n");
    const mine = Buffer.from("에이전트가 덮어쓰려던 내용\n");
    await transport.writeNewFile(target, current, 0o644);

    const staleHash = sha256(Buffer.from("5분 전 내용\n"));
    const w = await transport.overwriteFile(target, mine, 0o644, { expectedSha256: staleHash });
    assert.equal(w.ok, false, "다른 세션/사람이 바꿨으면 덮어쓰면 안 된다");
    assert.equal(w.stage, "concurrency");
    assert.equal(w.currentSha256, sha256(current));
    assert.match(w.reason, /덮어쓰지 않았다/);

    const read = await transport.readFile(target, 1024 * 1024);
    assert.equal(read.buffer.equals(current), true, "낙관적 동시성 검사가 실패하면 원격 내용이 그대로여야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("6) overwriteFile: 검증 실패 시 백업으로 되돌린다 (rolledBack)", T, async () => {
    const dir = sub("rollback");
    const target = join(dir, "rollback.txt");
    const original = Buffer.from("원래 내용\n");
    const replacement = Buffer.from("바뀐 내용\n");
    const backup = Buffer.from("이전 세션 백업\n");
    await transport.writeNewFile(target, original, 0o644);

    // 검증 단계를 강제로 실패시킨다(전송 계층 소스는 고치지 않고 인스턴스 메서드만 바꾼다).
    const realVerify = transport.verifyWritten.bind(transport);
    transport.verifyWritten = async () => ({ ok: false, stage: "verify", reason: "테스트가 강제한 검증 실패" });
    let result;
    try {
      result = await transport.overwriteFile(target, replacement, 0o644, { backup });
    } finally {
      transport.verifyWritten = realVerify;
    }

    assert.equal(result.ok, false);
    assert.equal(result.stage, "verify");
    assert.equal(result.rolledBack, true, "백업이 있으면 반드시 되돌려야 한다");
    const read = await transport.readFile(target, 1024 * 1024);
    assert.equal(read.buffer.equals(backup), true, "되돌린 뒤 원격 내용은 백업과 같아야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("7) 바이너리 왕복: NUL/0xFF/non-UTF8 바이트가 손상되지 않는다", T, async () => {
    const dir = sub("binary");
    const target = join(dir, "blob.bin");
    const bytes = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x81, 0x7f, 0x00, 0xc3, 0x28, 0xe9, 0x00, 0xab]);
    // latin1 문자열(비 UTF-8)도 섞어서 보낸다.
    const latin = Buffer.from([0xe3, 0xea, 0xb5, 0xa5, 0x20, 0x41, 0x00, 0x42], "latin1");
    const payload = Buffer.concat([bytes, Buffer.from("---"), latin, Buffer.from([0x00])]);

    const w = await transport.writeNewFile(target, payload, 0o644);
    assert.equal(w.ok, true, w.reason);
    assert.equal(w.sha256, sha256(payload));

    const read = await transport.readFile(target, 1024 * 1024);
    assert.equal(read.ok, true, read.reason);
    assert.equal(read.buffer.length, payload.length);
    assert.equal(read.buffer.equals(payload), true, "바이너리가 바이트 단위로 보존되어야 한다");
    assert.equal(read.sha256, sha256(payload));
    // 큰 바이너리도 한 번에.
    const big = Buffer.alloc(300 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = (i * 7 + 13) & 0xff;
    const bigPath = join(dir, "big-mixed.bin");
    assert.equal((await transport.writeNewFile(bigPath, big, 0o644)).ok, true);
    const bigRead = await transport.readFile(bigPath, 4 * 1024 * 1024);
    assert.equal(bigRead.buffer.equals(big), true, "300KB 혼합 바이너리도 정확히 왕복해야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("8) deleteFile: 삭제 성공 / 두 번째 삭제 실패 / 디렉터리는 재귀 삭제되지 않는다", T, async () => {
    const dir = sub("delete");
    const file = join(dir, "gone.txt");
    await transport.writeNewFile(file, Buffer.from("x\n"), 0o644);

    const d1 = await transport.deleteFile(file);
    assert.equal(d1.ok, true, d1.reason);
    assert.equal(existsSync(file), false);

    const d2 = await transport.deleteFile(file);
    assert.equal(d2.ok, false, "이미 없는 파일 삭제는 실패해야 한다");
    assert.ok(d2.reason.length > 0);

    const sub2 = join(dir, "nested");
    await transport.mkdir(sub2, true);
    writeFileSync(join(sub2, "child.txt"), "child\n");
    const d3 = await transport.deleteFile(sub2);
    assert.equal(d3.ok, false, "디렉터리를 파일 삭제로 지우면 안 된다(조용한 재귀 삭제 금지)");
    assert.equal(existsSync(sub2), true, "디렉터리가 남아 있어야 한다");
    assert.equal(existsSync(join(sub2, "child.txt")), true, "하위 파일도 남아 있어야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("9) move: 새 이름 이동 / 기존 대상은 overwrite 없이 실패 / overwrite 는 서버 지원 여부에 따라", T, async () => {
    const dir = sub("move");
    const src = join(dir, "from.txt");
    const dst = join(dir, "to.txt");
    const content = Buffer.from("이동될 내용\n");
    await transport.writeNewFile(src, content, 0o644);

    // (1) 대상이 없을 때: 이동 성공
    const okMove = await transport.move(src, dst, false);
    assert.equal(okMove.ok, true, okMove.reason);
    assert.equal(existsSync(src), false);
    assert.equal(readFileSync(dst).equals(content), true);

    // (2) 대상이 있고 overwrite 미지정: 실패 + 대상 보존
    const other = join(dir, "other.txt");
    await transport.writeNewFile(src, Buffer.from("출발\n"), 0o644);
    await transport.writeNewFile(other, Buffer.from("대상\n"), 0o644);
    const noOverwrite = await transport.move(src, other, false);
    assert.equal(noOverwrite.ok, false, "overwrite 없이 기존 대상을 덮으면 안 된다");
    assert.match(noOverwrite.reason, /이미 존재|overwrite/);
    assert.equal(readFileSync(other, "utf8"), "대상\n", "실패한 이동이 대상을 지우거나 바꿔서는 안 된다");
    assert.equal(existsSync(src), true, "실패한 이동이 원본을 지우면 안 된다");

    // (3) overwrite:true — 서버가 posix-rename 를 광고했는지에 따라 갈린다.
    assert.equal(server.posixRenameAdvertised(), true, "가짜 서버가 posix-rename 확장을 광고하는지 먼저 확인");
    assert.equal(transport.client.sftp._extensions["posix-rename@openssh.com"], "1");
    const withOverwrite = await transport.move(src, other, true);
    assert.equal(withOverwrite.ok, true, withOverwrite.reason);
    assert.equal(readFileSync(other, "utf8"), "출발\n", "원자적 덮어쓰기가 반영되어야 한다");
    assert.equal(existsSync(src), false);
  });

  test("9b) move: posix-rename 미지원 서버 + overwrite 는 조용히 지우지 않고 실패시킨다", T, async () => {
    const dir = sub("move-noposhix");
    const src = join(dir, "a.txt");
    const dst = join(dir, "b.txt");
    await transport.writeNewFile(src, Buffer.from("출발\n"), 0o644);
    await transport.writeNewFile(dst, Buffer.from("대상\n"), 0o644);

    server.disablePosixRename();
    let r;
    try {
      r = await transport.move(src, dst, true);
    } finally {
      server.enablePosixRename();
    }
    assert.equal(r.ok, false, "원자적 덮어쓰기를 못 하는 서버는 실패시켜야 한다");
    assert.match(r.reason, /posix-rename/);
    assert.equal(readFileSync(dst, "utf8"), "대상\n", "기존 대상이 지워지거나 바뀌면 안 된다");
    assert.equal(existsSync(src), true, "원본도 남아 있어야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("10) mkdir: recursive 로 중첩 디렉터리 생성 / 기존 경로는 예외 없이 처리", T, async () => {
    const dir = sub("mkdir");
    const nested = join(dir, "a", "b", "c");

    const m1 = await transport.mkdir(nested, true);
    assert.equal(m1.ok, true, m1.reason);
    assert.equal(existsSync(nested), true);
    assert.equal(m1.mode !== undefined, true, "생성된 모드가 보고되어야 한다");

    // 이미 있는 경로: 크래시 없이 성공(또는 명확한 실패) — 여기선 성공으로 떨어진다.
    const m2 = await transport.mkdir(nested, true);
    assert.equal(m2.ok, true, m2.reason);
    assert.equal(existsSync(nested), true);

    // 파일과 겹치는 경로는 실패해야 한다.
    const asFile = join(dir, "as-file");
    await transport.writeNewFile(asFile, Buffer.from("x"), 0o644);
    const m3 = await transport.mkdir(asFile, true);
    assert.equal(m3.ok, false, "기존 파일을 디렉터리로 만들면 안 된다");
    assert.ok(m3.reason.length > 0);
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("11) chmod: 모드 변경 반영 + addsExecuteBit 판정", T, async () => {
    const dir = sub("chmod");
    const target = join(dir, "script.sh");
    await transport.writeNewFile(target, Buffer.from("#!/bin/sh\n"), 0o644);

    const st0 = await transport.stat(target);
    assert.equal(st0.ok, true, st0.reason);
    assert.equal(st0.attrs.mode & 0o777, 0o644);

    const c1 = await transport.chmod(target, 0o600);
    assert.equal(c1.ok, true, c1.reason);
    assert.equal(c1.afterMode & 0o777, 0o600);
    assert.equal(c1.beforeMode & 0o777, 0o644);

    const st1 = await transport.stat(target);
    assert.equal(st1.attrs.mode & 0o777, 0o600, "stat 으로 실제 모드가 확인되어야 한다");

    // 0644 → 0755: 실행 비트가 붙는다 → §1 고위험 플래그가 true 여야 한다.
    const c2 = await transport.chmod(target, 0o755);
    assert.equal(c2.ok, true, c2.reason);
    assert.equal(c2.addsExecuteBit, true, "실행 비트 추가로 판정되어야 한다");
    assert.equal(c2.afterMode & 0o777, 0o755);

    // 0755 → 0700: 실행 비트는 여전히 있으니 addsExecuteBit 은 false (새로 추가된 게 아님).
    const c3 = await transport.chmod(target, 0o700);
    assert.equal(c3.ok, true, c3.reason);
    assert.equal(c3.addsExecuteBit, false, "이미 있던 실행 비트는 '추가'가 아니다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("12) listDir: name/type/size 와 심볼릭 링크 항목", T, async () => {
    const dir = sub("listdir");
    await transport.writeNewFile(join(dir, "file-a.txt"), Buffer.alloc(1234, 0x61), 0o644);
    mkdirSync(join(dir, "sub"), { recursive: true });
    symlinkSync("file-a.txt", join(dir, "link-a.txt"));

    const l = await transport.listDir(dir);
    assert.equal(l.ok, true, l.reason);
    const byName = Object.fromEntries(l.entries.map((e) => [e.name, e]));

    assert.ok(byName["file-a.txt"], "파일 항목이 있어야 한다");
    assert.equal(byName["file-a.txt"].type, "file");
    assert.equal(byName["file-a.txt"].size, 1234);

    assert.ok(byName.sub, "디렉터리 항목이 있어야 한다");
    assert.equal(byName.sub.type, "dir");

    assert.ok(byName["link-a.txt"], "심볼릭 링크 항목이 있어야 한다");
    assert.equal(byName["link-a.txt"].type, "symlink", "심볼릭 링크는 type 'symlink' 으로 보여야 한다");
    for (const e of l.entries) {
      assert.equal(typeof e.name, "string");
      assert.equal(typeof e.type, "string");
      assert.equal(typeof e.size, "number");
    }

    const missing = await transport.listDir(join(dir, "nope"));
    assert.equal(missing.ok, false);
    assert.ok(missing.reason.length > 0);
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("13) 쓰기 권한 거부(EACCES)가 명확한 한국어 메시지로 surfaced 된다", T, async (t) => {
    if (IS_ROOT) {
      t.skip("root 로 실행 중이라 0o500 디렉터리에도 쓸 수 있다 — 권한 거부 시나리오를 재현할 수 없음");
      return;
    }
    const dir = sub("eacces");
    const readOnly = join(dir, "ro");
    mkdirSync(readOnly, { recursive: true });
    chmodSync(readOnly, 0o500); // r-x: 읽기/실행만
    try {
      const w = await transport.writeNewFile(join(readOnly, "nope.txt"), Buffer.from("x"), 0o644);
      assert.equal(w.ok, false, "쓰기 불가 디렉터리인데 성공하면 안 된다");
      assert.ok(
        /권한|거부|denied/i.test(w.reason),
        `권한 거부 이유가 명확해야 한다: ${w.reason}`,
      );
      assert.ok(/권한 거부/.test(w.reason), "메시지가 '권한 거부' 라는 문구를 포함해야 한다");
      assert.equal(existsSync(join(readOnly, "nope.txt")), false, "실패한 쓰기가 파일을 만들면 안 된다");
    } finally {
      chmodSync(readOnly, 0o755);
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("14) withPathLock: 같은 경로 직렬화 — 병렬 호출이 겹치지 않는다", T, async () => {
    const lockKey = "w:/srv/www/shared/lock-demo.txt";
    let active = 0;
    let maxActive = 0;
    let counter = 0;
    const order = [];

    await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        transport.withPathLock(lockKey, async () => {
          active++;
          maxActive = Math.max(maxActive, active);
          order.push(`enter-${i}`);
          await new Promise((r) => setTimeout(r, 20));
          counter++;
          order.push(`exit-${i}`);
          active--;
        }),
      ),
    );

    assert.equal(counter, 5, "다섯 블록이 모두 실행되어야 한다");
    assert.equal(maxActive, 1, "동일 경로 잠금은 동시에 하나만 들어갈 수 있다");
    // enter/exenter 가 교차하면(중첩) 실패 — 반드시 enter → exit 가 쌍을 이룬다.
    for (let i = 0; i < order.length; i += 2) {
      assert.match(order[i], /^enter-/);
      assert.match(order[i + 1], /^exit-/);
    }

    // 서로 다른 잠 키는 서로를 막지 않는다.
    let parallelMax = 0;
    let parallelActive = 0;
    await Promise.all(
      [0, 1, 2].map((i) =>
        transport.withPathLock(`w:other-${i}`, async () => {
          parallelActive++;
          parallelMax = Math.max(parallelMax, parallelActive);
          await new Promise((r) => setTimeout(r, 20));
          parallelActive--;
        }),
      ),
    );
    assert.equal(parallelMax, 3, "서로 다른 경로 잠은 병렬로 동작해야 한다");
  });

  // ─────────────────────────────────────────────────────────────────────────
  test("15) close() 후 ensureConnected() 가 지연 재연결된다", T, async () => {
    assert.equal((await transport.ensureConnected()).ok, true);
    await transport.close();
    assert.equal(transport.status().connected, false, "close 후에는 연결이 없어야 한다");
    assert.equal(transport.status().connectedAt, null); // status() 는 0 을 null 로 정규화한다

    const again = await transport.ensureConnected();
    assert.equal(again.ok, true, `재연결이 실패했다: ${again.error}`);
    assert.equal(transport.status().connected, true);
    assert.ok(transport.status().jailRoot, "재연결 후 jail 루트가 다시 확인되어야 한다");

    // 재연결 뒤에도 실제 작업이 된다.
    const dir = sub("reconnect");
    const target = join(dir, "after-reconnect.txt");
    const w = await transport.writeNewFile(target, Buffer.from("다시 붙었다\n"), 0o644);
    assert.equal(w.ok, true, w.reason);
    assert.equal(readFileSync(target, "utf8"), "다시 붙었다\n");
  });

  test("16) 진단: readFile 은 크기 상한과 디렉터리를 거부한다", T, async () => {
    const dir = sub("read-guard");
    const big = join(dir, "big.txt");
    await transport.writeNewFile(big, Buffer.alloc(5000, 0x62), 0o644);

    const tooBig = await transport.readFile(big, 100);
    assert.equal(tooBig.ok, false, "상한을 넘는 파일은 통째로 받지 않아야 한다");
    assert.match(tooBig.reason, /너무 큼/);
    assert.equal(tooBig.size, 5000, "실제 크기는 알려줘야 한다(상한만 알면 부족하다)");

    const isDir = await transport.readFile(dir, 1024 * 1024);
    assert.equal(isDir.ok, false);
    assert.match(isDir.reason, /디렉터리/);

    const gone = await transport.readFile(join(dir, "missing.txt"), 1024 * 1024);
    assert.equal(gone.ok, false);
    assert.ok(gone.reason.length > 0);
  });

  test("17) probeWrite: 쓰기 가능 여부 진단이 실제로 동작한다", T, async () => {
    const dir = sub("probe");
    const p = await transport.probeWrite(dir, 0o644);
    assert.equal(p.ok, true, `probeWrite 실패: ${p.reason}`);
    assert.equal(p.cleanedUp, true, "진단 파일은 스스로 지워져야 한다");
    assert.equal(existsSync(p.target), false, "진단 파일이 남으면 안 된다");
  });

  test("18) 진단: 이벤트로 연결/오류가 기록된다 (비밀값 미포함)", T, async () => {
    const kinds = new Set(events.map((e) => e.kind));
    assert.ok(kinds.has("connected"), "연결 성공 이벤트가 기록되어야 한다");
    for (const e of events) {
      assert.equal(typeof e.kind, "string");
      assert.equal(typeof e.message, "string");
      assert.ok(!e.message.includes("test-pass"), "이벤트에 비밀번호가 남으면 안 된다");
    }
  });
});
