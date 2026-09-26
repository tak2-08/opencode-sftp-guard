// config.mjs / redact.mjs 초기화 경로 테스트 — §0 "설정 실패는 조용히 넘어가지 않는다".
//
// 특히 중요한 것: 비밀 파일이 없거나 권한이 느슨하면 플러그인은 *도구가 사라지는 게 아니라*
// 모든 sftp_* 툴이 명시적으로 실패하는 상태로 초기화된다(plugin.ts createDisabledPlugin).
// 이 테스트는 그 결정의 입력(로더 동작)을 고정한다.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigError, DEFAULT_CONNECTION, loadPolicy, loadSecrets } from "../lib/core/config.mjs";
import { clearSecrets, listSecretLabels, scrubText } from "../lib/core/redact.mjs";

const T = { timeout: 20000 };

function withSecretsFile(content, mode, fn) {
  const dir = mkdtempSync(join(tmpdir(), "sftpguard-cfg-"));
  const file = join(dir, "sftp-secrets.json");
  try {
    if (content !== null) {
      writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content), "utf8");
      if (mode !== null) chmodSync(file, mode);
    }
    return fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("config.mjs — 비밀 파일 로드(§0)", () => {
  test("파일 없음 → ConfigError + 조작 가능한 안내(플러그인은 전 도구 비활성으로 폴백)", T, () => {
    clearSecrets();
    withSecretsFile(null, null, (file) => {
      let err;
      try {
        loadSecrets(file);
      } catch (e) {
        err = e;
      }
      assert.ok(err instanceof ConfigError, "ConfigError 여야 한다");
      assert.match(err.message, /sftp-secrets\.json/);
      assert.match(err.message, /chmod 600/, "권한 복구 방법을 알려줘야 한다");
      assert.equal(listSecretLabels().length, 0, "실패한 로드는 비밀을 등록하지 않는다");
    });
  });

  test("권한이 느슨함(group/other 접근) → 거부(비밀은 644 면 이미 유출된 것)", T, () => {
    clearSecrets();
    withSecretsFile({ connection: { host: "127.0.0.1", port: 22, username: "sftp-guard-user" }, password: "pw-value-1234" }, 0o644, (file) => {
      assert.throws(() => loadSecrets(file), (e) => e instanceof ConfigError && /chmod 600/.test(e.message));
      assert.equal(listSecretLabels().length, 0, "거부된 파일의 비밀은 등록되지 않는다");
    });
  });

  test("권한 600 + 비밀번호 → 로드되고 비밀값이 redact 등록소에 들어간다", T, () => {
    clearSecrets();
    withSecretsFile({ connection: { host: "127.0.0.1", port: 22, username: "sftp-guard-user" }, password: "pw-value-1234" }, 0o600, (file) => {
      const loaded = loadSecrets(file);
      assert.equal(loaded.connection.username, "sftp-guard-user", "전용 SFTP 계정(비밀 파일에서 온 값)");
      assert.equal(loaded.connection.host, "127.0.0.1", "§0.1 루프백(공개 도메인 아님)");
      assert.equal(loaded.connection.port, 22);
      assert.ok(listSecretLabels().includes("sftp.password"), "비밀은 등록소에 있어야 이후 모든 출구가 스크럽된다");
      assert.ok(!scrubText("연결 실패: pw-value-1234").includes("pw-value-1234"), "로딩 직후부터 스크럽된다");
      clearSecrets();
    });
  });

  test("환경변수 기반 비밀은 거부(§0 — 셸 환경은 모델의 bash 로 노출된다)", T, () => {
    clearSecrets();
    withSecretsFile({ connection: { host: "127.0.0.1", port: 22, username: "sftp-guard-user" }, passwordFromEnv: true }, 0o600, (file) => {
      assert.throws(() => loadSecrets(file), (e) => e instanceof ConfigError && /환경변수/.test(e.message));
      clearSecrets();
    });
    // SFTP_GUARD_PASSWORD 가 실제로 설정돼 있어도 거부해야 한다.
    withSecretsFile({ connection: { host: "127.0.0.1", port: 22, username: "sftp-guard-user" }, password: "pw-value-1234" }, 0o600, (file) => {
      const prev = process.env.SFTP_GUARD_PASSWORD;
      process.env.SFTP_GUARD_PASSWORD = "from-env-1234";
      try {
        assert.throws(() => loadSecrets(file), (e) => e instanceof ConfigError && /환경변수/.test(e.message));
      } finally {
        if (prev === undefined) delete process.env.SFTP_GUARD_PASSWORD;
        else process.env.SFTP_GUARD_PASSWORD = prev;
        clearSecrets();
      }
    });
  });

  test("password 와 privateKeyPath 가 둘 다 없으면 거부", T, () => {
    clearSecrets();
    withSecretsFile({ connection: { host: "127.0.0.1", port: 22, username: "sftp-guard-user" } }, 0o600, (file) => {
      assert.throws(() => loadSecrets(file), (e) => e instanceof ConfigError && /password 도 privateKeyPath 도 없음/.test(e.message));
    });
  });

  test("잘못된 JSON → 원본 조각을 노출하지 않는 오류", T, () => {
    clearSecrets();
    withSecretsFile("{ password: 'pw-value-1234',,, broken", 0o600, (file) => {
      let err;
      try {
        loadSecrets(file);
      } catch (e) {
        err = e;
      }
      assert.ok(err instanceof ConfigError);
      assert.ok(!err.message.includes("pw-value-1234"), "파싱 오류 메시지에 비밀 조각이 새면 안 된다");
      assert.match(err.message, /JSON/);
    });
  });

  test("기본 연결값: 루프백 + 22, 그리고 계정명은 기본값이 없다", T, () => {
    assert.equal(DEFAULT_CONNECTION.host, "127.0.0.1", "공개 도메인/DDNS 가 아니라 컨테이너→호스트 루프백");
    assert.equal(DEFAULT_CONNECTION.port, 22);
    assert.equal(
      DEFAULT_CONNECTION.username,
      "",
      "계정명을 소스에 박아두지 않는다 — 배포 저장소에 사용자 이름이 새고, 설정 누락이 조용한 실패를 만들지 않도록",
    );
  });
});

describe("config.mjs — 정책 로드(fail-closed)", () => {
  test("파일 없음 → 내장 기본값(모두 fail-closed 방향)", T, () => {
    const dir = mkdtempSync(join(tmpdir(), "sftpguard-pol-"));
    try {
      const p = loadPolicy(join(dir, "nonexistent.json"));
      assert.equal(p.requireLiveGate, true, "게이트 실측성 검사는 기본 켜짐");
      assert.equal(p.allowModelApproveAll, false, "모델이 approve-all 을 켤 수 없다");
      assert.equal(p.auditor.enabled, false, "감사자 모드는 기본 꺼짐");
      assert.equal(p.approvalTimeoutMs, 600000, "기본 10분");
      assert.equal(p.approveAllBatchCap, 20);
      assert.deepEqual(p.allowedRoots, ["/var/www/html", "/srv/remote-sandbox"], "환경 특이 경로를 소스에 박지 않는다");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("allowedRoots 가 비면 로드 실패(fail-closed)", T, () => {
    const dir = mkdtempSync(join(tmpdir(), "sftpguard-pol-"));
    try {
      const file = join(dir, "policy.json");
      writeFileSync(file, JSON.stringify({ allowedRoots: [] }));
      assert.throws(() => loadPolicy(file), (e) => e instanceof ConfigError && /allowedRoots/.test(e.message));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("중첩 limits 와 평평한 키를 모두 받아들이고, 평평한 키가 우선", T, () => {
    const dir = mkdtempSync(join(tmpdir(), "sftpguard-pol-"));
    try {
      const file = join(dir, "policy.json");
      writeFileSync(
        file,
        JSON.stringify({ limits: { maxReadBytes: 1024, maxWriteBytes: 2048 }, maxWriteBytes: 4096, approvalTimeoutMs: 1 }),
      );
      const p = loadPolicy(file);
      assert.equal(p.maxReadBytes, 1024, "중첩 limits 적용");
      assert.equal(p.maxWriteBytes, 4096, "평평한 키가 우선");
      assert.ok(p.approvalTimeoutMs >= 5000, "타임아웃 하한(5초)보다 작아질 수 없다");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("예시 정책 파일이 실제 로더를 통과한다(배포 예제가 깨져 있으면 안 된다)", T, () => {
    const here = new URL("..", import.meta.url).pathname;
    const p = loadPolicy(join(here, "sftp-guard.config.example.json"));
    assert.deepEqual(p.allowedRoots, ["/var/www/html", "/srv/remote-sandbox"]);
    assert.equal(p.auditor.agent, "risk-auditor");
    assert.equal(p.auditor.maxRetries, 2, "§4 재시도 상한");
    assert.ok(p.auditPath, "로그 경로가 계산된다");
  });
});
