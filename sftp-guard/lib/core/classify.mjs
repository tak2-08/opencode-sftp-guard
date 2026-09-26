// 위험 분류기 — §1.
// 확장자 + 경로 + 내용 + chmod 를 함께 보고 최종 판정을 낸다.
import { CONTENT_RISK, describeContentRisk, scanContent } from "./scan.mjs";

export const RISK = {
  STATIC: "static", // 무해: 승인 매트릭스의 "static" 행
  HIGH: "high", // 서버에서 실행될 수 있거나 실행을 바꾸는 파일
  HARD: "hard", // deny-list: 어떤 게이트도 인간 승인 없이는 통과 불가
};

/** 서버에서 실행 가능한 확장자(§1 목록 + 흔한 추가분). */
const EXECUTABLE_EXTENSIONS = new Set([
  "php", "phtml", "php3", "php4", "php5", "php6", "php7", "php8", "phps", "phar",
  "cgi", "pl", "pm", "py", "pyc", "rb", "sh", "bash", "zsh", "ksh", "jsp", "jspx",
  "asp", "aspx", "ashx", "asmx", "cer", "exe", "dll", "so", "jar", "war", "ear",
  "ps1", "psm1", "vbs", "vbe", "jscript", "wsf", "hta", "scpt", "apk", "bin",
  "lua", "tcl", "r", "go", "class",
]);

/**
 * 웹서버/시스템 설정 파일.
 * §1: "웹서버 설정 파일 중 다른 파일의 실행 동작을 바꾸는 것(.htaccess, .user.ini,
 * nginx.conf 조각, web.config)".
 * §4: 이런 파일은 deny-list(감사자 override 불가 → 항상 인간 escalate)다.
 *
 * ★ 판정은 "정확한 이름" 기준이다. `.user.ini.bak` 처럼 접두사가 같은 백업 파일은
 *   웹서버가 읽지 않으므로 static 으로 둔다 — 과잉 판정은 승인 프롬프트 피로를 만들어
 *   사람이 "무조건 허용"을 누르게 만드는, 실제로는 위험한 부작용이 있다.
 */
const CONFIG_BASENAMES = new Set([
  // 웹서버가 실제로 읽는 실행 규칙 파일(하드)
  ".htaccess", ".user.ini", "web.config", ".htpasswd",
  // 그 밖의 서버/시스템 설정(하드 — §4 "서버 설정 파일")
  "php.ini", "nginx.conf", "httpd.conf", "apache2.conf", "sshd_config", "sudoers",
  "crontab", "authorized_keys", "my.cnf", "supervisord.conf", ".npmrc", "known_hosts",
  "fstab", "hosts", "resolv.conf",
]);

/** cgi-bin 계열 경로(§1). */
const CGI_PATH_RE = /(^|\/)(?:cgi-bin|cgi-bin2|fcgi-bin|wsgi)(?:\/|$)/i;

/**
 * 경로 문자열만 보고 확장자/경로 위험을 뽑는다.
 * 이중 확장자(shell.php.jpg) 를 놓치지 않도록 basename 의 모든 점을 검사한다.
 * @param {string} path POSIX 경로
 */
export function analyzePath(path) {
  const p = String(path ?? "");
  const segments = p.split("/").filter((s) => s.length > 0);
  const base = segments.length ? segments[segments.length - 1] : "";
  const lowerBase = base.toLowerCase();

  // 1) 점(.)으로 잘린 모든 조각을 확장자 후보로 본다.
  const dottedParts = lowerBase.split(".").slice(1).filter((s) => s.length > 0);
  const extensions = [...new Set(dottedParts)];

  const matchedExtensions = extensions.filter((e) => EXECUTABLE_EXTENSIONS.has(e));

  // 2) 실행 파일의 확장자를 뒤에 mere 뒤집어붙인 이중 확장자도 고위험이다.
  const doubleExtMatched = [];
  for (let i = 0; i < extensions.length; i++) {
    if (!EXECUTABLE_EXTENSIONS.has(extensions[i])) continue;
    // 예: .php.jpg → 뒤에 오는 조각이 이미지/문서 확장자여도 실행 가능하다.
    const trailing = extensions.slice(i + 1);
    if (trailing.length > 0) doubleExtMatched.push(extensions[i]);
  }

  // 3) 설정 파일명.
  const isConfigBasename = CONFIG_BASENAMES.has(lowerBase);
  // 4) 숨김 파일 + 실행 확장자 조합은 특히 위험(예: .bashrc 에 exec).
  const isHidden = lowerBase.startsWith(".");

  // 5) cgi-bin 경로.
  const inCgiPath = CGI_PATH_RE.test(p);

  const reasons = [];
  if (matchedExtensions.length) reasons.push(`실행 가능 확장자: .${matchedExtensions.join(", .")}`);
  if (doubleExtMatched.length) reasons.push(`이중 확장자 위장: .${doubleExtMatched.join(", .")} + 뒤쪽 확장자`);
  if (isConfigBasename) reasons.push(`웹서버/시스템 설정 파일명: ${base}`);
  if (inCgiPath) reasons.push("cgi-bin 경로");
  if (isHidden && (matchedExtensions.length || isConfigBasename)) reasons.push(`숨김 파일(.${base})`);

  return {
    base,
    extensions,
    matchedExtensions,
    doubleExtMatched: [...new Set(doubleExtMatched)],
    isConfigBasename,
    isHidden,
    inCgiPath,
    pathRisk: matchedExtensions.length > 0 || doubleExtMatched.length > 0 || isConfigBasename || inCgiPath,
    reasons,
  };
}

/**
 * 최종 분류.
 * @param {object} input
 * @param {string} input.path 대상 경로
 * @param {Buffer|string} [input.content] 이번 쓰기로 넣을 내용(신규 파일일 때)
 * @param {Buffer|string} [input.existingContent] 기존 파일 내용(편집 시 서명에 사용)
 * @param {{addsExecuteBit?: boolean}} [input.flags] chmod 등
 * @param {number} [input.maxScanBytes]
 * @returns {{risk: string, hard: boolean, pathAnalysis: object, contentScan: object|null, reasons: string[], summary: string}}
 */
export function classifyTarget(input) {
  const pathAnalysis = analyzePath(input.path);
  const reasons = [...pathAnalysis.reasons];

  // 내용은 "새로 쓰는 내용"을 우선 판정한다. 편집이면 새 내용 + 기존 내용 둘 다 본다.
  let contentScan = null;
  const primary = input.content !== undefined ? input.content : input.existingContent;
  if (primary !== undefined && primary !== null) {
    contentScan = scanContent(primary, { maxBytes: input.maxScanBytes });
    if (contentScan.risk !== CONTENT_RISK.NONE) reasons.push(describeContentRisk(contentScan));
    if (contentScan.truncated) reasons.push(`본문 일부만 검사됨 (${contentScan.scannedBytes}/${contentScan.totalBytes}B)`);
  }

  // 편집 대상이 이미 위험 파일이면, "내용이 깨끗해 보여도" 위험은 사라지지 않는다(§1 마지막 문장).
  const existingScan =
    input.content !== undefined && input.existingContent !== undefined && Buffer.isBuffer(input.existingContent) && input.existingContent.length
      ? scanContent(input.existingContent, { maxBytes: input.maxScanBytes })
      : null;
  if (existingScan && existingScan.risk !== CONTENT_RISK.NONE) {
    reasons.push(`기존 파일 내용도 위험 시그니처 보유: ${describeContentRisk(existingScan)}`);
    contentScan = mergeHarder(contentScan, existingScan);
  }

  const hardContent = contentScan?.risk === CONTENT_RISK.HARD;
  const addsExecuteBit = Boolean(input.flags?.addsExecuteBit);

  // hard 판정: webshell 하드 시그니처 / 웹서버 설정 파일 / 실행 비트가 붙는 chmod
  const hard = hardContent || pathAnalysis.isConfigBasename || addsExecuteBit;
  // high 판정: 실행 가능 확장자, cgi-bin, 실행 확장자 위장, 의심 내용
  const high =
    pathAnalysis.matchedExtensions.length > 0 ||
    pathAnalysis.doubleExtMatched.length > 0 ||
    pathAnalysis.inCgiPath ||
    contentScan?.risk === CONTENT_RISK.SUSPECT ||
    addsExecuteBit;

  const risk = hard ? RISK.HARD : high ? RISK.HIGH : RISK.STATIC;
  return {
    risk,
    hard,
    pathAnalysis,
    contentScan,
    reasons,
    summary:
      risk === RISK.STATIC
        ? "static (정적 파일)"
        : `${risk === RISK.HARD ? "HARD-DENY" : "HIGH-RISK"}: ${reasons.join(" | ") || "실행 가능성 의심"}`,
  };
}

function mergeHarder(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (b.risk === CONTENT_RISK.HARD || a.risk !== CONTENT_RISK.HARD) return b;
  return a;
}

/**
 * §2/§4 의 "deny-list(감사자도 override 불가)" 판정.
 *  - 하드 시그니처 웹셸
 *  - 웹서버 설정 파일
 *  - 인증/세션/자격증명/결제 관련 파일
 */
const SENSITIVE_PATH_TOKENS = [
  "auth", "login", "logout", "session", "credential", "password", "passwd", "secret",
  "token", "apikey", "api_key", "oauth", "saml", "jwt", "payment", "pay", "billing",
  "card", "checkout", "stripe", "iam", "permission", "acl", "key", "cert", "ssh",
];
const SENSITIVE_BASENAME_RE = /^(\.env|wp-config|configuration|config_local|secrets?|credentials?|id_rsa|id_ed25519|known_hosts|htpasswd)/i;

/** deny-list 하드 디니에스(escalate-only) 대상인지 판정. */
export function isHardDeniedTarget(classification, relativeName = "") {
  if (classification?.risk === RISK.HARD) return { denied: true, why: classification.summary };
  const scan = classification?.contentScan;
  if (scan?.risk === CONTENT_RISK.HARD) return { denied: true, why: `웹셸 하드 시그니처: ${describeContentRisk(scan)}` };
  const name = String(relativeName || classification?.pathAnalysis?.base || "");
  if (SENSITIVE_BASENAME_RE.test(name)) return { denied: true, why: `자격증명/설정 파일명: ${name}` };
  const lower = name.toLowerCase();
  if (lower.endsWith(".env") || lower.endsWith(".env.local") || lower.endsWith(".env.production")) {
    return { denied: true, why: `환경 변수 파일: ${name}` };
  }
  return { denied: false };
}

/** 경로 조각에 민감 토큰이 있는지(deny-list 용도, 오탐을 감수하고 넓게 잡는다). */
export function hasSensitivePathToken(relativePath) {
  const parts = String(relativePath ?? "")
    .split("/")
    .filter(Boolean)
    .map((s) => s.toLowerCase());
  return parts.filter((p) => SENSITIVE_PATH_TOKENS.some((t) => p === t || p.includes(t)));
}
