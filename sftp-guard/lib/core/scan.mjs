// 내용 기반 위험 판정 — §1 "extension 과 무관한 에스컬레이션".
//
// 설계 원칙(중요):
//  - 여기서 "위험"은(new file/기존 file 불문) 사람의 손이 아니라 *실행* 가능해지는 것을 막기 위한 것.
//  - 오탐(FP)이 많아지면 에이전트가 쓸 수 없게 되고, FN 이 생기면 웹셸이 통과한다.
//    따라서 "치명적(hard)" 과 "의심(suspect)" 을 두 단계로 나눈다.
//    hard → deny-list 로 승격되어 어떤 게이트에서도 인간 승인을 넘길 수 없다.
//    suspect → 고위험(high-risk) 분류에 합류해 항상 인간 승인이 필요하다.
//  - 정규식은 모두 개행/공백을 관대하게 허용한다(난독화 우회 방지)지만,
//    정규식 하나가 파일 전체를 훑는 비용을 넘지 않도록 본문은 상한 바이트에서만 검사한다.

// 검사할 본문 상한(초과분은 "미검사"로 명시한다). 4 MiB.
export const DEFAULT_SCAN_BYTES = 4 * 1024 * 1024;

/** 하드 시그니처: 존재만 하면 그 파일은 사람이 직접 확인해야 한다(감사자도 override 불가). */
const HARD_CONTENT_SIGNATURES = [
  { id: "php-open-tag", re: /<\?(?:php|=)?\b/i, why: "PHP 여는 태그" },
  { id: "asp-open-tag", re: /<%\s*(?:@|=)?(?:language\s*=\s*["']?vbscript)?/i, why: "ASP 여는 태그" },
  // 이 superglobal 조합은 웹셸 판정의 사실상 표준 시그니처다.
  { id: "php-superglobal-exec", re: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*(?:\[[^\]\n]{0,80}\]|\{[^\}\n]{0,80}\})?\s*(?:\(|\bin\s)/i, why: "슈퍼글로벌을 코드 위치에 사용" },
  { id: "preg-replace-e", re: /preg_replace\s*\(\s*(?:'[^']*'|"[^"]*")\s*,\s*['"]\w*e['"]/i, why: "preg_replace /e 수정자" },
  { id: "assert-code", re: /\bassert\s*\(\s*(?:['"$]|base64_decode|gzinflate|str_rot13)/i, why: "assert() 에 코드 인자" },
  { id: "create-function", re: /\bcreate_function\s*\(/i, why: "create_function() 동적 함수 생성" },
  // webshell 를 "코드" 로 전개하는 흔한 조합들.
  { id: "callable-from-request", re: /\b(?:call_user_func(?:_array)?|array_map|usort|ob_start|extract)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$.{0,20}base64_decode)/i, why: "입력값을 실행 가능한 위치로 전달" },
];

/**
 * 의심 시그니처: 단독으로는 webshell 확정이 아니지만 "고위험" 분류를 만든다.
 * 정상 PHP/JS 도 대개 포함하므로 hard 로 승격하지 않는다.
 */
const SUSPECT_CONTENT_SIGNATURES = [
  { id: "eval", re: /\beval\s*\(/i, why: "eval(" },
  { id: "system", re: /\bsystem\s*\(/i, why: "system(" },
  { id: "exec", re: /\bexec\s*\(/i, why: "exec(" },
  { id: "shell-exec", re: /\bshell_exec\s*\(/i, why: "shell_exec(" },
  { id: "passthru", re: /\bpassthru\s*\(/i, why: "passthru(" },
  { id: "proc-open", re: /\bproc_open\s*\(/i, why: "proc_open(" },
  { id: "popen", re: /\bpopen\s*\(/i, why: "popen(" },
  { id: "pwn", re: /\bpwn\s*\(/i, why: "pwn(" },
  { id: "backtick-exec", re: /`[^`\n]{1,200}`/, why: "백틱 실행" },
  { id: "base64-decode", re: /\bbase64_decode\s*\(/i, why: "base64_decode(" },
  { id: "gzinflate", re: /\b(?:gzinflate|gzuncompress)\s*\(/i, why: "gzinflate(" },
  { id: "str-rot13", re: /\bstr_rot13\s*\(/i, why: "str_rot13(" },
  { id: "php-file-write", re: /\b(?:file_put_contents|fwrite)\s*\(/i, why: "파일 쓰기 함수" },
  { id: "php-exec-bit", re: /\bchmod\s*\(\s*[^)]*0?7[0-7]{2}/i, why: "chmod 실행 비트 부여" },
  { id: "node-child-process", re: /\b(?:child_process|execSync|spawnSync)\b/, why: "노드 프로세스 실행" },
  { id: "jsp-runtime", re: /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/, why: "JSP Runtime.exec" },
];

/**
 * 이스케이프/난독화 흔적(가산점). 단독으론 위험 아니지만 다른 시그니처와 함께 있으면 가중치.
 */
const OBFUSCATION_SIGNATURES = [
  { id: "hex-escape-run", re: /(?:\\x[0-9a-f]{2}){6,}/i, why: "긴 16진수 이스케이프 덩어리" },
  { id: "unicode-escape-run", re: /(?:\\u[0-9a-f]{4}){6,}/i, why: "긴 유니코드 이스케이프 덩어리" },
  { id: "long-base64-blob", re: /[A-Za-z0-9+/]{200,}={0,2}/, why: "긴 base64 덩어리" },
  { id: "chr-concat", re: /(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}/i, why: "chr() 문자열 조립" },
];

/** 스캔 결과 요약 형태. */
export const CONTENT_RISK = {
  NONE: "none",
  SUSPECT: "suspect",
  HARD: "hard",
};

/**
 * 본문 위험 스캔.
 * @param {Buffer|string} content 검사할 내용
 * @param {{maxBytes?: number}} [opts]
 * @returns {{risk: string, scannedBytes: number, totalBytes: number, truncated: boolean,
 *            hard: Array<{id: string, why: string, sample: string}>,
 *            suspect: Array<{id: string, why: string, sample: string}>,
 *            obfuscation: Array<{id: string, why: string}>, text: string}}
 */
export function scanContent(content, opts = {}) {
  const maxBytes = opts.maxBytes ?? DEFAULT_SCAN_BYTES;
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content ?? ""), "utf8");
  const totalBytes = buf.length;
  const view = buf.subarray(0, maxBytes);
  const truncated = totalBytes > view.length;
  // 확장자 판정과 무관하게 항상 문자열로 본다(NUL 로 중단하지 않는다).
  const text = view.toString("utf8");

  const hard = [];
  const suspect = [];
  const obfuscation = [];
  const seen = new Set();

  for (const sig of HARD_CONTENT_SIGNATURES) {
    const m = firstMatch(text, sig.re);
    if (m) hard.push({ id: sig.id, why: sig.why, sample: sample(m, text) });
  }
  for (const sig of SUSPECT_CONTENT_SIGNATURES) {
    if (seen.has(sig.id)) continue;
    const m = firstMatch(text, sig.re);
    if (m) {
      seen.add(sig.id);
      suspect.push({ id: sig.id, why: sig.why, sample: sample(m, text) });
    }
  }
  for (const sig of OBFUSCATION_SIGNATURES) {
    if (firstMatch(text, sig.re)) obfuscation.push({ id: sig.id, why: sig.why });
  }

  const risk = hard.length > 0 ? CONTENT_RISK.HARD : suspect.length > 0 || obfuscation.length > 0 ? CONTENT_RISK.SUSPECT : CONTENT_RISK.NONE;
  return { risk, scannedBytes: view.length, totalBytes, truncated, hard, suspect, obfuscation, text };
}

function firstMatch(text, re) {
  const m = re.exec(text);
  return m ? { index: m.index, match: m[0] } : null;
}

function sample({ index, match }, text) {
  const from = Math.max(0, index - 20);
  const to = Math.min(text.length, index + match.length + 20);
  const ctx = text.slice(from, to).replace(/\s+/g, " ");
  return ctx.length > 160 ? `${ctx.slice(0, 160)}…` : ctx;
}

/**
 * 내용만 보고 "이건 webshell 로 보여야 한다" 를 한 문장으로 요약(로그/승인 화면용).
 * verdict 가 'high' 인 경우 호출된다.
 */
export function describeContentRisk(scan) {
  if (scan.risk === CONTENT_RISK.NONE) return "내용 위험 시그니처 없음";
  const parts = [];
  if (scan.hard.length) parts.push(`치명적: ${scan.hard.map((h) => `${h.why}[${h.id}]`).join(", ")}`);
  if (scan.suspect.length) parts.push(`의심: ${scan.suspect.map((s) => s.why).join(", ")}`);
  if (scan.obfuscation.length) parts.push(`난독화 흔적: ${scan.obfuscation.map((o) => o.why).join(", ")}`);
  if (scan.truncated) parts.push(`(본문 ${scan.totalBytes}B 중 ${scan.scannedBytes}B만 검사됨)`);
  return parts.join(" / ");
}
