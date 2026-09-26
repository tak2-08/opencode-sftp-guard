// 순수 로직 단위 테스트 — classify / scan / paths / diff / redact / audit / policy.
// 네트워크·디스크(감사 로그 제외)·opencode 런타임에 의존하지 않는다.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RISK, analyzePath, classifyTarget, hasSensitivePathToken, isHardDeniedTarget } from "../lib/core/classify.mjs";
import { CONTENT_RISK, scanContent } from "../lib/core/scan.mjs";
import {
  guardPath,
  isUnder,

  matchScope,
  normalizeLexical,
  scopeRelative,
  splitParent,
  whichRoot,
} from "../lib/core/paths.mjs";
import { applyExactReplaces, buildDiff, diffSummary, lineDiff, toLines } from "../lib/core/diff.mjs";
import {
  clearSecrets,
  isSensitiveKey,
  listSecretLabels,
  maskCredentialLikeValues,
  registerSecret,
  safeError,
  safeErrorMessage,
  scrubDeep,
  scrubText,
} from "../lib/core/redact.mjs";
import { APPROVER, AuditLog } from "../lib/core/audit.mjs";
import {
  ACTION,
  DECISION,
  PERMISSION,
  buildChmodPreview,
  buildDeletePreview,
  buildModePreview,
  buildMovePreview,
  buildScopePreview,
  buildWritePreview,
  decide,
} from "../lib/core/policy.mjs";
import { sha256 } from "../lib/core/util.mjs";

const T = { timeout: 20000 };

// ═══════════════════════════════════════════════════════════════════════════
// classify.mjs
// ═══════════════════════════════════════════════════════════════════════════
describe("classify.mjs — §1 위험 분류", () => {
  test("php 확장자 + 깨끗한 본문 → high 이며 hard 가 아니다", T, () => {
    const r = classifyTarget({ path: "/var/www/html/a.php", content: Buffer.from("function noop() { return 1; }\n") });
    // 주의: 본문에 "<?php" 가 있으면 HARD_CONTENT_SIGNATURES(php-open-tag) 에 걸리므로
    // "plain content" 는 PHP 여는 태그 없이 구성해야 high 판정이 의미를 가진다.
    assert.equal(r.risk, RISK.HIGH);
    assert.equal(r.hard, false);
    assert.ok(r.pathAnalysis.matchedExtensions.includes("php"));
  });

  test("본문에 <?php 가 있으면 → hard", T, () => {
    const r = classifyTarget({ path: "/var/www/html/notes.txt", content: Buffer.from("안녕 <?php echo 1; ?>") });
    assert.equal(r.risk, RISK.HARD);
    assert.equal(r.hard, true);
    assert.ok(r.contentScan.hard.some((h) => h.id === "php-open-tag"));
  });

  test("확장자와 무관하게 본문 webshard 서명이면 hard (예: .jpg 안의 PHP)", T, () => {
    const r = classifyTarget({
      path: "/var/www/html/x.jpg",
      content: Buffer.from("<?php system($_GET['c']); ?>"),
    });
    assert.equal(r.risk, RISK.HARD, "이미지 확장자라도 실행 가능한 본문이면 hard 로 승격되어야 한다");
    assert.equal(r.hard, true);
    assert.ok(r.contentScan.hard.some((h) => h.id === "php-open-tag"));
  });

  test(".htaccess → hard + isConfigBasename", T, () => {
    const r = classifyTarget({ path: "/var/www/html/.htaccess", content: Buffer.from("Options +ExecCGI\n") });
    assert.equal(r.risk, RISK.HARD);
    assert.equal(r.pathAnalysis.isConfigBasename, true);
  });

  test(".user.ini.bak → static (웹서버가 읽지 않는 백업 파일 — 과잉 판정 회피)", T, () => {
    // 웹서버/PHP-FPM 은 정확히 ".user.ini" 만 읽는다. 접두사 규칙을 넓히면 승인 프롬프트 피로가 생겨
    // 사람이 "무조건 허용"을 누르게 되는 역효과가 있다(§1 과잉 판정의 실제 위험).
    const r = classifyTarget({ path: "/var/www/html/.user.ini.bak", content: Buffer.from("auto_prepend_file=x\n") });
    assert.equal(r.risk, RISK.STATIC);
    assert.equal(r.pathAnalysis.isConfigBasename, false);
  });

  test(".htaccess.bak → static, 그러나 정확한 .htaccess 는 hard", T, () => {
    assert.equal(classifyTarget({ path: "/var/www/html/backup/.htaccess.bak" }).risk, RISK.STATIC);
    assert.equal(classifyTarget({ path: "/var/www/html/.HTACCESS" }).risk, RISK.HARD, "대소문자 무시");
  });

  test("이중 확장자 위장 shell.php.jpg → high + doubleExtMatched 에 php", T, () => {
    const r = classifyTarget({ path: "/var/www/html/shell.php.jpg", content: Buffer.from("그냥 이미지 supposedly") });
    assert.equal(r.risk, RISK.HIGH);
    assert.ok(r.pathAnalysis.doubleExtMatched.includes("php"));
  });

  test("cgi-bin 경로의 .sh → high + inCgiPath", T, () => {
    const r = classifyTarget({ path: "/var/www/html/cgi-bin/run.sh", content: Buffer.from("#!/bin/sh\necho hi\n") });
    assert.equal(r.risk, RISK.HIGH);
    assert.equal(r.pathAnalysis.inCgiPath, true);
  });

  test("정적 css → static", T, () => {
    const r = classifyTarget({ path: "/var/www/html/css/site.css", content: Buffer.from("body{color:red}") });
    assert.equal(r.risk, RISK.STATIC);
    assert.equal(r.hard, false);
  });

  test("js 본문의 eval( → high + suspect 에 eval 포함", T, () => {
    const r = classifyTarget({ path: "/var/www/html/js/app.js", content: Buffer.from("eval(x);") });
    assert.equal(r.risk, RISK.HIGH);
    assert.ok(r.contentScan.suspect.some((s) => s.id === "eval"), "의심 시그니처 목록에 eval 이 있어야 한다");
  });

  test("기존 고위험 파일 편집은 '내용이 깨끗해 보여도' static 이 되지 않는다 (§1)", T, () => {
    const r = classifyTarget({
      path: "/var/www/html/a.php",
      content: Buffer.from("<?php\n// 이번 변경분은 안전해 보인다\n"),
      existingContent: Buffer.from("<?php eval($_GET[1]);"),
    });
    assert.notEqual(r.risk, RISK.STATIC, "기존 내용이 위험하면 편집 결과도 static 으로 내려가면 안 된다");
    assert.equal(r.risk, RISK.HARD);
  });

  test("오탐 주의: 주석/문자열 안의 system( 도 high 로 잡는다 (static 으로 만들지 않는다)", T, () => {
    // 의도된 오탐 방향: 안전함을 우선해 위험을 낮추지 않는다(오탐 < 누락).
    const r = classifyTarget({
      path: "/var/www/html/lib/helper.js",
      content: Buffer.from("// 예시: system('ls -la') 라고 적어두었다\nconst s = 'system(';\n"),
    });
    assert.equal(r.risk, RISK.HIGH, "의심 시그니처는 단독으로 high 를 만든다 — 이 기대값이 문서화 대상");
    assert.ok(r.contentScan.suspect.some((s) => s.id === "system"));
  });

  test("scanContent: 상한을 넘는 본문은 truncated 로 명시한다", T, () => {
    const big = Buffer.alloc(2048, 0x61);
    const s = scanContent(big, { maxBytes: 100 });
    assert.equal(s.truncated, true);
    assert.equal(s.scannedBytes, 100);
    assert.equal(s.totalBytes, 2048);
  });

  test("analyzePath: 실행 확장자 목록과 이중 확장자 판정", T, () => {
    const a = analyzePath("/x/a.phtml");
    assert.deepEqual(a.matchedExtensions, ["phtml"]);
    assert.equal(a.pathRisk, true);
    const b = analyzePath("/x/a.txt.php.docx");
    assert.deepEqual(b.doubleExtMatched, ["php"]);
  });

  test("isHardDeniedTarget: deny-list 4종", T, () => {
    const htaccess = classifyTarget({ path: "/var/www/html/.htaccess", content: Buffer.from("deny from all\n") });
    assert.equal(isHardDeniedTarget(htaccess).denied, true);

    const shell = classifyTarget({ path: "/var/www/html/u.php", content: Buffer.from("<?php eval($_POST['x']); ?>") });
    assert.equal(isHardDeniedTarget(shell).denied, true);

    const creds = classifyTarget({
      path: "/var/www/html/config/credentials.php",
      content: Buffer.from("<?php\nreturn ['user' => 'x'];\n"),
    });
    assert.equal(isHardDeniedTarget(creds).denied, true);

    // .env 는 분류 자체는 static 이지만 파일명 규칙으로 deny-list 에 오른다.
    const env = classifyTarget({ path: "/var/www/html/.env", content: Buffer.from("FOO=bar\n") });
    assert.equal(env.risk, RISK.STATIC);
    assert.equal(isHardDeniedTarget(env).denied, true, "환경 변수 파일은 내용은 무관하게 deny-list");
  });

  test("isHardDeniedTarget: 평범한 css 는 거부되지 않는다", T, () => {
    const css = classifyTarget({ path: "/var/www/html/css/site.css", content: Buffer.from("body{color:red}") });
    assert.equal(isHardDeniedTarget(css).denied, false);
  });

  test("hasSensitivePathToken: auth/payment 계열 조각을 잡는다", T, () => {
    const toks = hasSensitivePathToken("modules/payment/charge.js");
    assert.ok(toks.includes("payment"));
    const toks2 = hasSensitivePathToken("app/auth/login.php");
    assert.ok(toks2.includes("auth"));
    assert.ok(toks2.some((t) => t.startsWith("login")));
    assert.deepEqual(hasSensitivePathToken("assets/css/site.css"), []);
  });

  test("CONTENT_RISK 상수 값이 코드/문서와 일치한다", T, () => {
    assert.deepEqual(CONTENT_RISK, { NONE: "none", SUSPECT: "suspect", HARD: "hard" });
    assert.deepEqual(RISK, { STATIC: "static", HIGH: "high", HARD: "hard" });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// paths.mjs
// ═══════════════════════════════════════════════════════════════════════════
describe("paths.mjs — §7 경로 가드", () => {
  test("isUnder: 접두사 경계 함정 (/var/www/html-evil 은 안이다)", T, () => {
    assert.equal(isUnder("/var/www/html", "/var/www/html-evil/x"), false);
    assert.equal(isUnder("/var/www/html", "/var/www/html/a"), true);
    assert.equal(isUnder("/var/www/html", "/var/www/html"), true);
    assert.equal(isUnder("/var/www/html/", "/var/www/html/a/b/"), true);
    assert.equal(isUnder("/var/www/html", "/var/www/htmlish"), false);
  });

  test("guardPath: `..` 는 어떤 위치에서도 거부된다", T, () => {
    const roots = ["/srv/www"];
    for (const p of [
      "/srv/www/../etc/passwd",
      "/srv/www/a/../../etc/passwd",
      "/srv/www/a/..",
      "/etc/../srv/www/a",
    ]) {
      const r = guardPath({ path: p, allowedRoots: roots });
      assert.equal(r.ok, false, `${p} 는 거부되어야 한다`);
      assert.match(r.reason, /\.\./);
    }
  });

  test("guardPath: NUL 바이트 거부", T, () => {
    const r = guardPath({ path: "/srv/www/a\u0000.php", allowedRoots: ["/srv/www"] });
    assert.equal(r.ok, false);
    assert.match(r.reason, /NUL/);
  });

  test("guardPath: 빈 문자열 거부", T, () => {
    const r = guardPath({ path: "", allowedRoots: ["/srv/www"] });
    assert.equal(r.ok, false);
    assert.match(r.reason, /빈 경로/);
  });

  test("guardPath: allowedRoots 밖(/etc/passwd) 거부 + 이유에 루트 목록", T, () => {
    const r = guardPath({ path: "/etc/passwd", allowedRoots: ["/srv/www", "/srv/data"] });
    assert.equal(r.ok, false);
    assert.match(r.reason, /허용 루트 밖/);
    assert.match(r.reason, /\/srv\/www/);
  });

  test("guardPath: allowedRoots 가 빈 배열이면 fail-closed", T, () => {
    const r = guardPath({ path: "/srv/www/a.css", allowedRoots: [] });
    assert.equal(r.ok, false);
    assert.match(r.reason, /allowedRoots/);
  });

  test("guardPath: 깨끗한 경로 통과 + 매칭된 루트 반환", T, () => {
    const r = guardPath({ path: "/srv/www/css/site.css", allowedRoots: ["/other", "/srv/www/"] });
    assert.equal(r.ok, true);
    assert.equal(r.path, "/srv/www/css/site.css");
    assert.equal(r.root, "/srv/www");
  });

  test("normalizeLexical: 역슬래시를 슬래시로, 결과는 언제나 POSIX 절대경로", T, () => {
    const r = normalizeLexical("srv\\www\\a.css");
    assert.equal(r.ok, true);
    assert.equal(r.path, "/srv/www/a.css");
  });

  test("matchScope: 정확 일치 / 디렉터리 접두사 / 가장 좁은 매치 / 불일치", T, () => {
    assert.deepEqual(matchScope(["/srv/www/a.css"], "/srv/www/a.css"), { inScope: true, matched: "/srv/www/a.css" });

    const dir = matchScope(["/srv/www"], "/srv/www/img/logo.png");
    assert.equal(dir.inScope, true);
    assert.equal(dir.matched, "/srv/www");

    const narrow = matchScope(["/srv/www", "/srv/www/img"], "/srv/www/img/logo.png");
    assert.equal(narrow.inScope, true);
    assert.equal(narrow.matched, "/srv/www/img", "더 좁은 매치가 이겨야 한다");

    assert.equal(matchScope(["/srv/www"], "/srv/other/a.css").inScope, false);
    assert.equal(matchScope(["/srv/www"], "/srv/wwwevil/a.css").inScope, false, "접두사 경계가 지켜져야 한다");
    assert.equal(matchScope(["/"], "/anything/at/all").inScope, true);
  });

  test("scopeRelative: 매칭 접두사를 벗겨 상대 경로를 준다", T, () => {
    assert.equal(scopeRelative("/srv/www", "/srv/www/img/a.png"), "img/a.png");
    assert.equal(scopeRelative(null, "/a/b"), null);
    // 알려진 특이 동작(보고함): matched 가 "/" 일 때 trimSlash("/") 가 "/" 를 그대로 돌려줘서
    // 접두사 제거가 일어나지 않는다 → 결과에 선행 슬래시가 남는다. 표시 전용 용도라 영향은 낮다.
    assert.equal(scopeRelative("/", "/a/b"), "a/b", "루트 스코프에서는 선행 슬래시가 남으면 안 된다");
  });

  test("splitParent: 디렉터리 / basename 분해", T, () => {
    assert.deepEqual(splitParent("/a/b/c"), { dir: "/a/b", base: "c", parent: "/a/b/c" });
    assert.equal(splitParent("/a/b/").dir, "/a");
    // 알려진 특이 동작(보고함): 루트 레벨 경로에서 parent 가 "//c" 로 만들어진다
    // (trimSlash("/") 가 "/" 를 반환하고 `${dir}/${base}` 로 이어붙이기 때문).
    // POSIX 는("//" 로 시작하는 경로의 처리를 구현에 맡겨 두었으므로 Linux 에서는 "/c" 와 동일하게
    // 동작하지만, 문자열 비교/로그 출력에서는 의도와 다르게 보인다.
    assert.deepEqual(splitParent("/c"), { dir: "/", base: "c", parent: "/c" }, "루트 레벨이어 // 가 되면 안 된다");
  });

  test("whichRoot: 여러 루트 중 어디에 들어 있는지", T, () => {
    assert.equal(whichRoot(["/srv/www", "/srv/data"], "/srv/data/x.bin"), "/srv/data");
    assert.equal(whichRoot(["/srv/www"], "/srv/data/x.bin"), null);
  });

  test("joinResolvedDir 는 제거됨(미사용 export — 경로 결합 로직이 두 벌 생기지 않도록)", async (t) => {
    const mod = await import("../lib/core/paths.mjs");
    assert.equal(mod.joinResolvedDir, undefined, "중복 경로 결합 헬퍼는 제거되어야 한다");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// diff.mjs
// ═══════════════════════════════════════════════════════════════════════════
describe("diff.mjs — §5 승인 화면용 diff", () => {
  test("buildDiff: 한 줄 변경 → added/removed 카운트와 +/- 줄 텍스트", T, () => {
    const d = buildDiff("alpha\nbravo\ncharlie\n", "alpha\nBRAVO\ncharlie\n");
    assert.equal(d.added, 1);
    assert.equal(d.removed, 1);
    assert.match(d.text, /^\+BRAVO$/m);
    assert.match(d.text, /^-bravo$/m);
    assert.equal(d.unchanged, 2);
    assert.match(diffSummary(d), /\+1 -1/);
  });

  test("buildDiff: 동일한 입력 → 0/0", T, () => {
    const d = buildDiff("a\nb\n", "a\nb\n");
    assert.equal(d.added, 0);
    assert.equal(d.removed, 0);
    assert.equal(d.unchanged, 2);
  });

  test("buildDiff: NUL 이 있는 바이너리 → binary === true", T, () => {
    const d = buildDiff(Buffer.from([0x41, 0x00, 0x42]), Buffer.from([0x41, 0x00, 0x43]));
    assert.equal(d.binary, true);
    assert.match(diffSummary(d), /binary payload/);
  });

  test("applyExactReplaces: 유일한 일치 → 적용", T, () => {
    const r = applyExactReplaces("hello world", [{ find: "world", replace: "sftp-guard" }]);
    assert.equal(r.ok, true);
    assert.equal(r.content, "hello sftp-guard");
    assert.deepEqual(r.applied, [{ index: 0, replaced: 1 }]);
  });

  test("applyExactReplaces: 여러 곳 일치 + all 없음 → 거부", T, () => {
    const r = applyExactReplaces("a-a-a", [{ find: "a", replace: "b" }]);
    assert.equal(r.ok, false);
    assert.match(r.reason, /all:true/);
    assert.equal(r.content, undefined, "거부된 경우 부분 적용된 내용이 돌려주어지면 안 된다");
  });

  test("applyExactReplaces: 여러 곳 일치 + all:true → 전부 교체", T, () => {
    const r = applyExactReplaces("a-a-a", [{ find: "a", replace: "b", all: true }]);
    assert.equal(r.ok, true);
    assert.equal(r.content, "b-b-b");
    assert.deepEqual(r.applied, [{ index: 0, replaced: 3 }]);
  });

  test("applyExactReplaces: find 가 없음 → 거부", T, () => {
    const r = applyExactReplaces("hello", [{ find: "nope", replace: "x" }]);
    assert.equal(r.ok, false);
    assert.match(r.reason, /없음/);
    assert.equal(r.content, undefined);
  });

  test("applyExactReplaces: 두 번째 수정이 실패하면 전체 철회(content undefined)", T, () => {
    const r = applyExactReplaces("keep this", [
      { find: "keep", replace: "KEEP" },
      { find: "없는 문자열", replace: "x" },
    ]);
    assert.equal(r.ok, false, "두 번째 수정이 실패하면 성공으로 취급하면 안 된다");
    assert.match(r.reason, /edits\[1\]/);
    assert.equal(r.content, undefined, "부분 적용본이 노출되면 안 된다");
  });

  test("applyExactReplaces: 빈 find 거부", T, () => {
    const r = applyExactReplaces("x", [{ find: "", replace: "y" }]);
    assert.equal(r.ok, false);
    assert.match(r.reason, /find/);
  });

  test("lineDiff / toLines: 줄 분해 계약", T, () => {
    assert.deepEqual(toLines(""), { lines: [], endsWithNewline: true, hadCR: false });
    const crlf = toLines("a\r\nb\r\n");
    assert.deepEqual(crlf.lines, ["a", "b"]);
    assert.equal(crlf.hadCR, true);
    const ops = lineDiff(["a"], ["a", "b"]);
    assert.deepEqual(ops.map((o) => o.type), ["eq", "add"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// redact.mjs
// ═══════════════════════════════════════════════════════════════════════════
describe("redact.mjs — §0 비밀값 제거", () => {
  before(() => clearSecrets());
  after(() => clearSecrets());

  test("registerSecret 후 safeErrorMessage 이 비밀값을 노출하지 않는다", T, () => {
    registerSecret("s3cr3t-value-123", "test-password");
    const msg = safeErrorMessage(new Error("pw=s3cr3t-value-123"));
    assert.ok(!msg.includes("s3cr3t-value-123"), "비밀값이 메시지에 남아 있으면 안 된다");
    assert.match(msg, /redacted/);
    assert.deepEqual(listSecretLabels(), ["test-password"]);
  });

  test("safeErrorMessage: Error 가 아닌 값도 다룬다", T, () => {
    registerSecret("s3cr3t-value-123", "test-password");
    assert.ok(!safeErrorMessage("token: s3cr3t-value-123").includes("s3cr3t-value-123"));
    const err = safeError(new Error("boom s3cr3t-value-123"));
    assert.ok(!err.message.includes("s3cr3t-value-123"));
  });

  test("scrubDeep: 민감 키의 값은 통째로 가려진다", T, () => {
    registerSecret("s3cr3t-value-123", "test-password");
    const out = scrubDeep({ password: "s3cr3t-value-123", user: "editor" });
    assert.equal(out.password, "[redacted]");
    assert.equal(out.user, "editor", "민감하지 않은 키의 값은 보존되어야 한다(과잉 마스킹 방지)");
    assert.ok(!JSON.stringify(out).includes("s3cr3t-value-123"));
  });

  test("scrubDeep: 순환 참조 / Buffer / 중첩 구조를 무사히 처리", T, () => {
    registerSecret("s3cr3t-value-123", "test-password");
    const node = { name: "n", child: null, buf: Buffer.from("hello"), list: [1, { token: "s3cr3t-value-123" }] };
    node.child = node;
    const out = scrubDeep(node);
    assert.equal(out.child, "[circular]");
    assert.match(out.buf, /^\[buffer 5B sha256:/);
    assert.equal(out.list[1].token, "[redacted]");
  });

  test("scrubText: 평문이 함께 있으면 인코딩 형태(base64/hex/URL)도 함께 지운다", T, () => {
    registerSecret("s3cr3t-value-123", "plain");
    const b64 = Buffer.from("s3cr3t-value-123", "utf8").toString("base64");
    const hex = Buffer.from("s3cr3t-value-123", "utf8").toString("hex");
    assert.ok(!scrubText(`a ${"s3cr3t-value-123"} b`).includes("s3cr3t-value-123"));

    const mixed = scrubText(`평문=s3cr3t-value-123 b64=${b64} hex=${hex}`);
    assert.ok(!mixed.includes("s3cr3t-value-123"), "평문이 남아 있으면 안 된다");
    assert.ok(!mixed.includes(b64), "base64 형태가 남아 있으면 안 된다");
    assert.ok(!mixed.includes(hex), "16진수 형태가 남아 있으면 안 된다");

    // URL 인코딩이 원본과 달라지는 비밀값(특수문자 포함).
    registerSecret("p@ss/w+rd#9", "urlencoded");
    const enc = encodeURIComponent("p@ss/w+rd#9");
    assert.notEqual(enc, "p@ss/w+rd#9", "이 값은 인코딩 전후가 달라야 의미가 있다");
    const scrubbed = scrubText(`평문=p@ss/w+rd#9 url=${enc}`);
    assert.ok(!scrubbed.includes(enc), "퍼센트 인코딩 형태가 남아 있으면 안 된다");
    assert.match(scrubbed, /redacted/);
  });

  test("인코딩 형태만 단독으로 있어도 redact 된다 (base64/hex/URL) — 평문 동반 조건 없음", T, () => {
    // 이전 구현은 `if (text.includes(secret))` 안에 인코딩 형태 치환을 넣어 평문이 없으면 base64/hex 가
    // 로그·에러에 그대로 남았다(§0 위반). 이제 각 형태를 독립적으로 검사한다.
    clearSecrets();
    registerSecret("s3cr3t-value-123", "plain");
    const b64 = Buffer.from("s3cr3t-value-123", "utf8").toString("base64");
    assert.equal(scrubText(`url=${b64}`), "url=«redacted»", "base64 단독 형태도 지워야 한다");
    const hex = Buffer.from("s3cr3t-value-123", "utf8").toString("hex");
    assert.equal(scrubText(`hex=${hex}`), "hex=«redacted»", "16진수 단독 형태도 지워야 한다");
    registerSecret("p@ss/w+rd#9", "urlencoded");
    const enc = encodeURIComponent("p@ss/w+rd#9");
    assert.equal(scrubText(`?x=${enc}`), "?x=«redacted»", "URL 인코딩 단독 형태도 지워야 한다");
    clearSecrets();
  });

  test("clearSecrets: 등록소를 비우면 다시 원문이 그대로 나온다", T, () => {
    registerSecret("s3cr3t-value-123", "temp");
    assert.notEqual(scrubText("s3cr3t-value-123"), "s3cr3t-value-123");
    clearSecrets();
    assert.equal(scrubText("s3cr3t-value-123"), "s3cr3t-value-123");
    assert.deepEqual(listSecretLabels(), []);
  });

  test("짧은 비밀값(4자 미만)은 등록하지 않는다 (오탐 방지)", T, () => {
    clearSecrets();
    registerSecret("ab", "too-short");
    assert.deepEqual(listSecretLabels(), []);
    assert.equal(scrubText("ab"), "ab");
  });

  test("isSensitiveKey: 알려진 키 이름 판정", T, () => {
    for (const k of ["password", "passwd", "api_key", "apiKey", "client_secret", "auth-token", "private_key"]) {
      assert.equal(isSensitiveKey(k), true, `${k} 는 민감 키여야 한다`);
    }
    for (const k of ["username", "path", "size", "tool"]) {
      assert.equal(isSensitiveKey(k), false, `${k} 는 민감 키가 아니다`);
    }
  });

  test("maskCredentialLikeValues: PHP define 상수 대입 값을 가린다", T, () => {
    const r = maskCredentialLikeValues("<?php\ndefine('DB_PASSWORD', 'hunter2');\n");
    assert.ok(r.masked >= 1);
    assert.ok(!r.text.includes("hunter2"));
    assert.match(r.text, /«masked»/);
  });

  test("maskCredentialLikeValues: key = \"value\" 대입 값을 가린다", T, () => {
    const r = maskCredentialLikeValues('password = "abc123"\ntoken: \'zzz99\'\n');
    assert.ok(r.masked >= 2);
    assert.ok(!r.text.includes("abc123"));
    assert.ok(!r.text.includes("zzz99"));
  });

  test("maskCredentialLikeValues: 대입 없는 자연어는 가리지 않는다 (오탐 방향)", T, () => {
    const r = maskCredentialLikeValues("the password is a tricky concept");
    assert.equal(r.masked, 0);
    assert.equal(r.text, "the password is a tricky concept");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// audit.mjs
// ═══════════════════════════════════════════════════════════════════════════
describe("audit.mjs — §6 감사 로그", () => {
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sftpguard-audit-"));
    clearSecrets();
  });
  after(() => {
    clearSecrets();
    rmSync(dir, { recursive: true, force: true });
  });

  const entry = (i) => ({
    ts: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    tool: "sftp_write",
    outcome: "allowed",
    approver: APPROVER.HUMAN,
    path: `/srv/www/file-${i}.txt`,
    bytes: 100 + i,
    reason: "사용자 확인",
  });

  test("append: JSONL 한 줄에 필수 필드가 모두 들어간다", T, () => {
    const p = join(dir, "a", "audit.log");
    const log = new AuditLog({ path: p });
    const res = log.append(entry(1));
    assert.equal(res.ok, true);
    assert.equal(typeof res.hash, "string");

    const lines = readFileSync(p, "utf8").trimEnd().split("\n");
    assert.equal(lines.length, 1);
    const rec = JSON.parse(lines[0]);
    for (const k of ["ts", "tool", "outcome", "approver", "hash", "prev"]) {
      assert.ok(k in rec, `감사 항목에 ${k} 필드가 있어야 한다`);
    }
    assert.equal(rec.prev, "0".repeat(64), "첫 줄의 prev 는 영 해시여야 한다");
    assert.equal(rec.path, "/srv/www/file-1.txt");
  });

  test("append: 두 번째 줄은 첫 줄의 hash 로 체인이 이어진다", T, () => {
    const p = join(dir, "chain", "audit.log");
    const log = new AuditLog({ path: p });
    const r1 = log.append(entry(1));
    const r2 = log.append(entry(2));
    const recs = log.tail(2);
    assert.equal(recs[1].prev, r1.hash);
    assert.equal(recs[1].hash, r2.hash);
  });

  test("verifyChain: 새 로그는 ok, 중간 줄 변조는 brokenAt 로 지적한다", T, () => {
    const p = join(dir, "verify", "audit.log");
    const log = new AuditLog({ path: p });
    for (let i = 0; i < 5; i++) assert.equal(log.append(entry(i)).ok, true);
    assert.deepEqual(log.verifyChain(), { ok: true, entries: 5 });

    // 두 번째 줄의 approver 를 바꾼다(내용 변조).
    const lines = readFileSync(p, "utf8").trimEnd().split("\n");
    const rec = JSON.parse(lines[1]);
    rec.approver = "auditor"; // 사람이 아니라 감사자 승인으로 위조
    lines[1] = JSON.stringify(rec);
    writeFileSync(p, `${lines.join("\n")}\n`);

    // 새 인스턴스로 다시 읽어 체인을 검증한다(메모리 캐시 우회).
    const reopened = new AuditLog({ path: p });
    const v = reopened.verifyChain();
    assert.equal(v.ok, false, "내용 변조는 반드시 감지되어야 한다");
    assert.equal(v.brokenAt, 2, "변조된 줄 번호를 알려야 한다");
    assert.match(v.reason, /hash 불일치/);
  });

  test("로테이션: 상한(64KiB 바닥값)을 넘으면 .1 파일이 생긴다", T, () => {
    const p = join(dir, "rotate", "audit.log");
    const log = new AuditLog({ path: p, maxBytes: 70000 });
    for (let i = 0; i < 1200; i++) {
      const r = log.append({ ...entry(i), padding: "x".repeat(200) });
      assert.equal(r.ok, true);
    }
    const rotated = `${p}.1`;
    assert.ok(readFileSync(rotated, "utf8").length > 0, "회전된 로그가 비어 있으면 안 된다");
    const mainSize = readFileSync(p, "utf8").length;
    assert.ok(mainSize <= 70000, `본 로그가 상한을 넘었다: ${mainSize}`);
    assert.ok(mainSize > 0);
  });

  test("비밀값은 감사 로그에 절대 남지 않는다", T, () => {
    clearSecrets();
    registerSecret("s3cr3t-value-123", "audit-secret");
    const p = join(dir, "secret", "audit.log");
    const log = new AuditLog({ path: p });
    log.append({ ...entry(1), note: "연결 문자열: s3cr3t-value-123" });
    const text = readFileSync(p, "utf8");
    assert.ok(!text.includes("s3cr3t-value-123"), "감사 로그에 비밀값이 남으면 안 된다");
    clearSecrets();
  });

  test("append: 쓰기 불가능한 경로에서도 절대 throw 하지 않는다", T, () => {
    // 스펙 예시인 /proc/x/y/z.log 는 이 컨테이너에서 mkdirSync 가 멈춰 버려(무한 대기) 쓸 수 없다.
    // 대신 "일반 파일 아래에 경로를 지은" 동일한 실패 상황(ENOTDIR)을 쓴다.
    const blocker = join(dir, "not-a-dir");
    writeFileSync(blocker, "I am a file\n");
    const log = new AuditLog({ path: join(blocker, "sub", "audit.log") });
    const r = log.append(entry(1));
    assert.equal(r.ok, false, "쓸 수 없는 경로면 반드시 ok:false 를 돌려줘야 한다");
    assert.equal(typeof r.reason, "string");
    assert.ok(r.reason.length > 0);
    assert.equal(log.writeErrors > 0, true, "쓰기 실패가 카운트되어야 한다");
  });

  test("enabled:false 면 아무것도 쓰지 않는다", T, () => {
    const p = join(dir, "off", "audit.log");
    const log = new AuditLog({ path: p, enabled: false });
    assert.deepEqual(log.append(entry(1)), { ok: false, reason: "audit disabled" });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// policy.mjs — §2 매트릭스 전수 (표 구동)
// ═══════════════════════════════════════════════════════════════════════════
describe("policy.mjs — §2 승인 매트릭스", () => {
  /** 기준 세션. */
  const session = (over = {}) => ({
    discoveryRoot: "/srv/www",
    scopePaths: ["/srv/www/public"],
    approveAll: false,
    auditorMode: false,
    autoApprovedCount: 0,
    batchCap: 5,
    ...over,
  });
  const target = (over = {}) => ({
    requested: "/srv/www/public/a.css",
    resolved: "/srv/www/public/a.css",
    kind: "file",
    inScope: true,
    root: "/srv/www",
    ...over,
  });
  const staticCls = classifyTarget({ path: "/srv/www/public/a.css", content: Buffer.from("body{color:red}") });
  const highCls = classifyTarget({ path: "/srv/www/app.js", content: Buffer.from("eval(x);") });
  const hardCls = classifyTarget({ path: "/srv/www/.htaccess", content: Buffer.from("deny from all\n") });
  const hardDenied = (cls) => isHardDeniedTarget(cls);

  const rows = [
    {
      name: "LIST — discoveryRoot 안",
      input: { action: ACTION.LIST, target: target({ inScope: false, resolved: "/srv/www/other/a.css" }), session: session(), classification: staticCls },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "READ — discoveryRoot 안",
      input: { action: ACTION.READ, target: target({ inScope: false, resolved: "/srv/www/other/a.css" }), session: session(), classification: staticCls },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "LIST — scopePaths 안",
      input: { action: ACTION.LIST, target: target(), session: session({ discoveryRoot: "/srv/other" }), classification: staticCls },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "READ — scopePaths 안",
      input: { action: ACTION.READ, target: target(), session: session({ discoveryRoot: "/srv/other" }), classification: staticCls },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "READ — 모든 범위 밖",
      input: {
        action: ACTION.READ,
        target: target({ inScope: false, resolved: "/srv/other/x.css" }),
        session: session(),
        classification: staticCls,
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.SCOPE);
        assert.equal(d.canAuditorApprove, false);
      },
    },
    {
      name: "READ — chroot 밖(kind=outside-root) 은 DENY",
      input: {
        action: ACTION.READ,
        target: target({ inScope: false, kind: "outside-root", resolved: "/etc/passwd" }),
        session: session(),
        classification: staticCls,
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.DENY);
        assert.equal(d.permission, undefined);
      },
    },
    {
      name: "WRITE_NEW — static + 범위 안",
      input: { action: ACTION.WRITE_NEW, target: target(), session: session(), classification: staticCls, hardDenied: hardDenied(staticCls) },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "WRITE_EDIT — static + 범위 안",
      input: { action: ACTION.WRITE_EDIT, target: target(), session: session(), classification: staticCls, hardDenied: hardDenied(staticCls) },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "WRITE_NEW — static + 범위 밖",
      input: {
        action: ACTION.WRITE_NEW,
        target: target({ inScope: false, resolved: "/srv/other/a.css" }),
        session: session(),
        classification: staticCls,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.WRITE);
      },
    },
    {
      name: "WRITE_* — static + approve-all → 자동 허용(배치 카운터 표시)",
      input: {
        action: ACTION.WRITE_NEW,
        target: target({ inScope: false, resolved: "/srv/other/a.css" }),
        session: session({ approveAll: true, autoApprovedCount: 2 }),
        classification: staticCls,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.APPROVE_ALL);
        assert.match(d.reason, /3\/5/, "배치 카운터가 이유에 포함되어야 한다");
      },
    },
    {
      name: "WRITE_* — static + approve-all + 배치 상한 도달 → ASK",
      input: {
        action: ACTION.WRITE_NEW,
        target: target(),
        session: session({ approveAll: true, autoApprovedCount: 5, batchCap: 5 }),
        classification: staticCls,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.WRITE);
        assert.match(d.reason, /한도 도달/);
      },
    },
    {
      name: "WRITE_* — high + 범위 안이어도 ASK (범위로 예외되지 않는다)",
      input: {
        action: ACTION.WRITE_EDIT,
        target: target({ resolved: "/srv/www/public/app.js" }),
        session: session(),
        classification: highCls,
        hardDenied: hardDenied(highCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.WRITE);
        assert.equal(d.risk, RISK.HIGH);
        assert.match(d.reason, /범위로 예외되지 않는다/);
      },
    },
    {
      name: "WRITE_* — high + 감사자 모드 → 감사자 승인 가능",
      input: {
        action: ACTION.WRITE_EDIT,
        target: target(),
        session: session({ auditorMode: true }),
        classification: highCls,
        hardDenied: hardDenied(highCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.approver, APPROVER.AUDITOR);
        assert.equal(d.canAuditorApprove, true);
      },
    },
    {
      name: "WRITE_* — hard(deny-list) + 감사자 모드여도 감사자 승인 불가",
      input: {
        action: ACTION.WRITE_NEW,
        target: target({ resolved: "/srv/www/.htaccess" }),
        session: session({ auditorMode: true }),
        classification: hardCls,
        hardDenied: hardDenied(hardCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.approver, APPROVER.HUMAN);
        assert.equal(d.canAuditorApprove, false, "deny-list 는 어떤 게이트로도 override 불가");
        assert.match(d.reason, /deny-list/);
      },
    },
    {
      name: "WRITE_* — hard + denyHardContentWrites 정책 → DENY",
      input: {
        action: ACTION.WRITE_NEW,
        target: target({ resolved: "/srv/www/.htaccess" }),
        session: session(),
        classification: hardCls,
        hardDenied: hardDenied(hardCls),
        policy: { denyHardContentWrites: true },
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.DENY);
        assert.equal(d.permission, undefined);
      },
    },
    {
      name: "WRITE_* — high + approve-all 이라도 자동 허용되지 않는다",
      input: {
        action: ACTION.WRITE_EDIT,
        target: target(),
        session: session({ approveAll: true }),
        classification: highCls,
        hardDenied: hardDenied(highCls),
      },
      expect: (d) => assert.equal(d.decision, DECISION.ASK),
    },
    {
      name: "DELETE — 범위 안 + approve-all 이라도 항상 ASK",
      input: {
        action: ACTION.DELETE,
        target: target(),
        session: session({ approveAll: true, auditorMode: true }),
        classification: staticCls,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.DELETE);
        assert.equal(d.canAuditorApprove, false);
        assert.equal(d.approver, APPROVER.HUMAN);
      },
    },
    {
      name: "MOVE — 범위 안 + approve-all 이라도 항상 ASK",
      input: {
        action: ACTION.MOVE,
        target: target(),
        session: session({ approveAll: true, auditorMode: true }),
        classification: staticCls,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.MOVE);
        assert.equal(d.canAuditorApprove, false);
      },
    },
    {
      name: "MKDIR — 범위 안 → ALLOW",
      input: {
        action: ACTION.MKDIR,
        target: target({ requested: "/srv/www/public/img", resolved: "/srv/www/public/img", kind: "absent" }),
        session: session(),
        classification: staticCls,
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "MKDIR — 범위 밖 → ASK",
      input: {
        action: ACTION.MKDIR,
        target: target({ requested: "/srv/other/x", resolved: "/srv/other/x", inScope: false, kind: "absent" }),
        session: session(),
        classification: staticCls,
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.MKDIR);
      },
    },
    {
      name: "CHMOD — 실행 비트 추가 → ASK (고위험과 동등)",
      input: {
        action: ACTION.CHMOD,
        target: target(),
        session: session(),
        classification: staticCls,
        addsExecuteBit: true,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.CHMOD);
        assert.match(d.reason, /실행 비트/);
      },
    },
    {
      name: "CHMOD — 실행 비트 없음 + 범위 안 → ALLOW",
      input: {
        action: ACTION.CHMOD,
        target: target(),
        session: session(),
        classification: staticCls,
        addsExecuteBit: false,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ALLOW);
        assert.equal(d.approver, APPROVER.SCOPE_AUTO);
      },
    },
    {
      name: "CHMOD — 실행 비트 없음 + 범위 밖 → ASK",
      input: {
        action: ACTION.CHMOD,
        target: target({ inScope: false, resolved: "/srv/other/a.css" }),
        session: session(),
        classification: staticCls,
        addsExecuteBit: false,
        hardDenied: hardDenied(staticCls),
      },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.CHMOD);
      },
    },
    {
      name: "SCOPE — 범위 승인 자체는 항상 인간 확인",
      input: { action: ACTION.SCOPE, target: target(), session: session() },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.SCOPE);
        assert.equal(d.canAuditorApprove, false);
      },
    },
    {
      name: "MODE — 권한 격하/상향도 항상 ASK",
      input: { action: ACTION.MODE, target: target(), session: session() },
      expect: (d) => {
        assert.equal(d.decision, DECISION.ASK);
        assert.equal(d.permission, PERMISSION.MODE);
        assert.equal(d.canAuditorApprove, false);
      },
    },
    {
      name: "알 수 없는 액션 → DENY (fail-closed)",
      input: { action: "teleport", target: target(), session: session() },
      expect: (d) => {
        assert.equal(d.decision, DECISION.DENY);
        assert.match(d.reason, /알 수 없는 액션/);
      },
    },
    {
      name: "액션 없음(undefined) → DENY (fail-closed)",
      input: { target: target(), session: session() },
      expect: (d) => assert.equal(d.decision, DECISION.DENY),
    },
  ];

  for (const row of rows) {
    test(`decide: ${row.name}`, T, () => {
      const d = decide(row.input);
      assert.equal(typeof d.reason, "string");
      assert.ok(d.reason.length > 0, "모든 판정은 이유를 남겨야 한다");
      row.expect(d);
    });
  }

  test("decide: 고위험 판정에 reason 에 분류 근거가 포함된다", T, () => {
    const d = decide({
      action: ACTION.WRITE_NEW,
      target: target(),
      session: session(),
      classification: highCls,
      hardDenied: hardDenied(highCls),
    });
    assert.match(d.reason, /eval\(/, "승인 화면에 근거가 보여야 한다");
  });

  test("decide: hardDenied 를 생략해도 risk HARD 는 감사자 승인이 불가하다 (방어심겹)", T, () => {
    // 이전 구현은 risk===HARD 분기에서 canAuditorApprove 를 auditorMode 만 보고 true 로 돌려겼다.
    // 정상 호출 경로(isHardDeniedTarget 결과를 항상 전달)에서는 앞 분기가 먼저 잡지만,
    // 호출자가 실수로 hardDenied 를 빠뜨리는 순간 .htaccess/web 셸을 감사자가 통과시킬 수 있었다.
    // 지금은 risk 자체로 deny 를 고정한다(§4: deny-list 는 감사자 override 불가).
    const d = decide({
      action: ACTION.WRITE_NEW,
      target: target({ resolved: "/srv/www/.htaccess" }),
      session: session({ auditorMode: true }),
      classification: hardCls,
    });
    assert.equal(d.decision, DECISION.ASK);
    assert.equal(d.canAuditorApprove, false, "hardDenied 미전달이어도 HARD 는 감사자 통과 불가");
    const d2 = decide({
      action: ACTION.WRITE_NEW,
      target: target({ resolved: "/srv/www/.htaccess" }),
      session: session({ auditorMode: true }),
      classification: hardCls,
      hardDenied: hardDenied(hardCls),
    });
    assert.equal(d2.canAuditorApprove, false, "hardDenied 전달 시에도 동일");
  });

});

// ═══════════════════════════════════════════════════════════════════════════
// policy.mjs — §5 승인 미리보기 빌더
// ═══════════════════════════════════════════════════════════════════════════
describe("policy.mjs — §5 승인 미리보기", () => {
  const diff = buildDiff(Buffer.from("a\nb\nc\n"), Buffer.from("a\nB\nc\nd\n"));

  // 앞선 매트릭스 스위트의 픽스처와 동일한 정의(스위트 간 상태 공유 금지).
  const target = { requested: "/srv/www/public/a.css", resolved: "/srv/www/public/a.css", kind: "file", inScope: true, root: "/srv/www" };
  const staticCls = classifyTarget({ path: "/srv/www/public/a.css", content: Buffer.from("body{color:red}") });
  const highCls = classifyTarget({ path: "/srv/www/app.js", content: Buffer.from("eval(x);") });
  const hardCls = classifyTarget({ path: "/srv/www/.htaccess", content: Buffer.from("deny from all\n") });

  /**
   * §5 계약: "파일 이름만 물어보는 승인" 은 허용되지 않는다.
   * 모든 프리뷰는 사람이 읽을 문장(patterns)과 본문 텍스트를 반드시 갖는다.
   */
  function assertPreviewShape(p, name) {
    assert.ok(typeof p.title === "string" && p.title.length > 0, `${name}: title 이 비었다`);
    assert.ok(Array.isArray(p.patterns) && p.patterns.length > 0, `${name}: patterns 가 비었다(승인 UI 에 맥락이 없다)`);
    assert.ok(typeof p.text === "string" && p.text.length > 0, `${name}: text 가 비었다`);
    assert.equal(typeof p.metadata, "object");
  }

  test("buildWritePreview: title/patterns/metadata.filepath/metadata.diff", T, () => {
    const p = buildWritePreview({
      target,
      classification: staticCls,
      diff,
      beforeSha: "a".repeat(64),
      afterSha: "b".repeat(64),
      action: ACTION.WRITE_EDIT,
    });
    assertPreviewShape(p, "buildWritePreview");
    assert.equal(p.metadata.filepath, target.resolved);
    assert.equal(p.metadata.diff, diff.text);
    assert.equal(p.metadata.risk, RISK.STATIC);
    assert.match(p.title, /기존 파일 수정/);
  });

  test("buildWritePreview: 바이너리 diff 는 본문을 싣지 않는다", T, () => {
    const bin = buildDiff(Buffer.from([0, 1, 2]), Buffer.from([0, 1, 3]));
    const p = buildWritePreview({ target, classification: staticCls, diff: bin, action: ACTION.WRITE_NEW });
    assert.equal(p.metadata.diff, "(binary payload — 본문 미표시)");
    assert.match(p.title, /신규 파일 작성/);
  });

  test("buildWritePreview: HARD 는 제목에 감사자 승인 불가가 명시된다", T, () => {
    const p = buildWritePreview({
      target: { ...target, resolved: "/srv/www/.htaccess" },
      classification: hardCls,
      diff,
      action: ACTION.WRITE_NEW,
    });
    assert.match(p.title, /HARD-DENY/);
    assert.match(p.title, /감사자 승인 불가/);
  });

  test("buildDeletePreview", T, () => {
    const p = buildDeletePreview({
      target,
      stat: { isDirectory: false, size: 1234 },
      sha256: "c".repeat(64),
      head: "첫 줄\n둘째 줄\n",
    });
    assertPreviewShape(p, "buildDeletePreview");
    assert.equal(p.metadata.filepath, target.resolved);
    assert.match(p.title, /삭제/);
  });

  test("buildMovePreview: 출발/도착/덮어쓰기 경고", T, () => {
    const p = buildMovePreview({
      from: "/srv/www/public/a.css",
      to: "/srv/www/public/b.css",
      stat: { size: 10 },
      sha256: "d".repeat(64),
      overwrite: true,
    });
    assertPreviewShape(p, "buildMovePreview");
    assert.match(p.text, /덮어쓴다/);
    assert.match(p.title, /→/);
  });

  test("buildScopePreview: 경로 목록과 탐색 결과", T, () => {
    const p = buildScopePreview({
      basePath: "/srv/www",
      paths: [
        { path: "/srv/www", kind: "directory" },
        { path: "/srv/www/public", kind: "directory" },
        { path: "/srv/www/new.css", kind: "absent", note: "새 파일" },
      ],
      entries: { total: 12, depth: 2, truncated: true, sample: ["/srv/www/a.css"] },
    });
    assertPreviewShape(p, "buildScopePreview");
    assert.match(p.title, /3개 경로/);
    assert.match(p.text, /절단 여부 예/);
  });

  test("buildChmodPreview: 실행 비트 경고와 8진 표기", T, () => {
    const p = buildChmodPreview({
      target,
      beforeMode: 0o644,
      afterMode: 0o755,
      addsExecuteBit: true,
    });
    assertPreviewShape(p, "buildChmodPreview");
    assert.match(p.title, /0644→0755/);
    assert.match(p.text, /고위험/);
  });

  test("buildModePreview", T, () => {
    const p = buildModePreview({ changes: ["approve-all 켜기"], current: "ask" });
    assertPreviewShape(p, "buildModePreview");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// util.mjs (diff/preview 가 의존하는 해시 계약)
// ═══════════════════════════════════════════════════════════════════════════
describe("util.mjs — sha256 계약", () => {
  test("Buffer 와 동등한 문자열은 같은 해시를 낸다", T, () => {
    assert.equal(sha256("hello"), sha256(Buffer.from("hello", "utf8")));
    assert.equal(sha256("hello").length, 64);
  });
});
