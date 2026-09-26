// 비밀값 제거(redaction) — §0 비협정 조항의 실행부.
//
// 규칙:
//  1) 이 모듈은 프로세스 전역 싱글턴이다. 비밀값은 플러그인 초기화 시 "한 번" 등록되고,
//     그 뒤로는 어떤 아웃바운드 경로(툴 출력/에러/로그/감사 로그)도 통과하기 전에 반드시
//     scrubRedact() 를 거친다.
//  2) 등록된 비밀값은 원문으로 어디에도 남기지 않는다(자기 자신도 로그하지 않는다).
//  3) 이 모듈은 절대 파일시스템/네트워크에 비밀값을 쓰지 않는다.
//  4) scrub 은 재귀적이며 깊이/길이 상한이 있다(순환 구조·대용량 입력 방지).
import { oneLine, sha256 } from "./util.mjs";

/** 등록된 비밀값 → 라벨. 값 자체는 키로만 쓴다. */
const secrets = new Map();
/** 라벨 → 안정적 지문(로그에 "무엇이" 등록됐는지만 보이게 한다). */
const fingerprints = new Map();

/** 최소 등록 길이. 이보다 짧은 문자열은 redact 해도 오탐이 더 크다. */
const MIN_SECRET_LEN = 4;

/**
 * 비밀값 등록. 같은 값이 두 번 등록되면 첫 라벨을 유지한다(라벨 흔들림 방지).
 * @param {unknown} value 비밀값(문자열/Buffer)
 * @param {string} label 로그에 노출 가능한 라벨
 */
export function registerSecret(value, label) {
  if (value === undefined || value === null) return;
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : String(value);
  if (text.length < MIN_SECRET_LEN) return; // 너무 짧으면 redact 자체가 위험(전체 문자열 오염)
  if (!secrets.has(text)) {
    secrets.set(text, label);
    fingerprints.set(label, `${sha256(text).slice(0, 8)}…(${text.length}B)`);
  }
}

/** 현재 등록된 라벨 목록(값은 절대 포함하지 않는다). */
export function listSecretLabels() {
  return Array.from(new Set(secrets.values())).sort();
}

/** 라벨별 등록 지문(값 없이). 진단 출력용. */
export function secretFingerprints() {
  return Object.fromEntries(fingerprints);
}

/** 테스트/셋다운용: 등록소를 비운다. */
export function clearSecrets() {
  secrets.clear();
  fingerprints.clear();
}

const URL_ENCODED = (text) => encodeURIComponent(text);

/**
 * 문자열/버퍼에서 등록된 비밀값을 전부 지운다.
 * 평문·URL 인코딩·base64·16진수 형태를 모두 시도한다.
 *
 * ★ 인코딩 형태는 "평문이 함께 들어 있을 때만" 지우면 안 된다(보안 결함).
 *   로그/에러에 인코딩된 값만 남는 경우(예: Authorization 헤더, URL 쿼리)가 실제로 발생하므로
 *   각 형태를 독립적으로 검사한다.
 */
export function scrubText(input) {
  let text = Buffer.isBuffer(input) ? input.toString("utf8") : typeof input === "string" ? input : String(input ?? "");
  if (text === "") return text;
  if (secrets.size === 0) return text;
  for (const secret of secrets.keys()) {
    // 평문
    if (text.includes(secret)) text = replaceAll(text, secret, "«redacted»");
    // base64 (인코딩된 형태가 원본보다 짧거나 같을 때만 의미가 있다)
    const b64 = base64Of(secret);
    if (b64.length >= 8 && text.includes(b64)) text = replaceAll(text, b64, "«redacted»");
    // 16진수
    const hex = Buffer.from(secret, "utf8").toString("hex");
    if (hex.length >= 8 && text.includes(hex)) text = replaceAll(text, hex, "«redacted»");
    // URL 퍼센트 인코딩 (특수문자가 있을 때만 원본과 다르다)
    const enc = URL_ENCODED(secret);
    if (enc !== secret && enc.length >= 4 && text.includes(enc)) text = replaceAll(text, enc, "«redacted»");
  }
  return text;
}

function base64Of(text) {
  try {
    return Buffer.from(text, "utf8").toString("base64");
  } catch {
    return "";
  }
}

function replaceAll(haystack, needle, replacement) {
  if (!needle) return haystack;
  return haystack.split(needle).join(replacement);
}

/** 알려진 민감 키 이름(스키마 무관하게 값 을 가린다). */
const SENSITIVE_KEY_RE =
  /(pass(word|wd|phrase)?|secret|token|api[_-]?key|private[_-]?key|credential|authorization|auth[_-]?token|session[_-]?key|access[_-]?key|client[_-]?secret)/i;

export function isSensitiveKey(key) {
  return SENSITIVE_KEY_RE.test(String(key ?? ""));
}

/**
 * 임의 값(객체/배열/에러)을 스크럽한 복사본으로 만든다.
 * - 비밀 값이 들어 있을 수 있는 키는 값을 "[redacted:라벨]" 로 통째로 교체한다.
 * - 문자열 값은 scrubText 를 통과한다.
 * - Error 는 message/stack/code 만 남기고 name 을 보존한다.
 * - 순환 참조는 "[circular]" 로 대체한다.
 */
export function scrubDeep(value, opts = {}) {
  const maxDepth = opts.maxDepth ?? 6;
  const maxString = opts.maxString ?? 20_000;
  const seen = new WeakSet();
  const walk = (node, depth, keyHint) => {
    if (node === null || node === undefined) return node;
    const t = typeof node;
    if (t === "string") {
      if (keyHint && isSensitiveKey(keyHint)) return "[redacted]";
      return truncate(scrubText(node), maxString);
    }
    if (t === "number" || t === "boolean") return node;
    if (t === "bigint") return node.toString();
    if (t === "function" || t === "symbol") return `[${t}]`;
    if (Buffer.isBuffer(node)) return `[buffer ${node.length}B sha256:${sha256(node).slice(0, 12)}]`;
    if (node instanceof Error) {
      return {
        name: node.name,
        message: truncate(scrubText(node.message), maxString),
        code: node.code === undefined ? undefined : scrubText(String(node.code)),
        stack: opts.includeStack ? truncate(scrubText(node.stack ?? ""), 4_000) : undefined,
      };
    }
    if (depth >= maxDepth) return "[depth-limit]";
    if (seen.has(node)) return "[circular]";
    seen.add(node);
    if (Array.isArray(node)) return node.slice(0, 200).map((v) => walk(v, depth + 1, keyHint));
    if (node instanceof Map) {
      const out = {};
      for (const [k, v] of node.entries()) out[String(k)] = walk(v, depth + 1, k);
      return out;
    }
    if (node instanceof Set) return Array.from(node.values()).slice(0, 200).map((v) => walk(v, depth + 1, keyHint));
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      if (typeof v === "function") continue;
      out[k] = walk(v, depth + 1, k);
    }
    return out;
  };
  return walk(value, 0, undefined);
}

function truncate(s, max) {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}…[+${s.length - max}chars]`;
}

/**
 * 모델/사용자에게 돌려줄 수 있는 형태로 Error 를 변환한다.
 * message/stack 어디에도 비밀값이 남지 않는다.
 */
export function safeError(err) {
  const scrubbed = scrubDeep(err, { includeStack: true, maxString: 2_000 });
  const message = typeof scrubbed === "object" && scrubbed && !Array.isArray(scrubbed) ? scrubbed.message : String(scrubbed);
  const out = new Error(typeof message === "string" ? message : "unknown error");
  if (typeof scrubbed === "object" && scrubbed?.code) out.code = scrubbed.code;
  if (typeof scrubbed === "object" && scrubbed?.stack) out.sftpGuardStack = scrubbed.stack;
  return out;
}

/** 사람이 읽을 수 있는 한 줄 오류 메시지(비밀값 제거 완료). */
export function safeErrorMessage(err) {
  return oneLine(scrubText(err instanceof Error ? err.message : String(err)), 500);
}

// ─────────────────────────────────────────────────────────────────────────────
// 읽기 결과의 "비밀처럼 보이는 값" 마스킹.
//
// SFTP 자격증명(§0)과는 별개지만, 읽기 결과를 모델 트랜스크립트로 넘기면
// 애플리케이션 자격증명(DB 비밀번호, API 키)이 대화 기록에 남는다.
// 설정값 스타일(키 = "값")만 대상으로 삼고, 주석/문서 예시는 오탐이 크므로 좁게 잡는다.
const CREDENTIAL_ASSIGNMENT_RE =
  /((?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|token)\s*[:=]\s*)(["'])([^"'\n]{3,120})\2/gi;
const PHP_CONST_ASSIGN_RE = /(define\s*\(\s*["'][A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN)[A-Z0-9_]*["']\s*,\s*)(["'])([^"'\n]{2,120})\2/gi;

/**
 * 텍스트에서 자격증명처럼 보이는 대입 값만 "«masked»" 로 바꾼다.
 * @returns {{text: string, masked: number}}
 */
export function maskCredentialLikeValues(input) {
  let text = Buffer.isBuffer(input) ? input.toString("utf8") : String(input ?? "");
  let masked = 0;
  text = text.replace(CREDENTIAL_ASSIGNMENT_RE, (_m, prefix, quote) => {
    masked++;
    return `${prefix}${quote}«masked»${quote}`;
  });
  text = text.replace(PHP_CONST_ASSIGN_RE, (_m, prefix, quote) => {
    masked++;
    return `${prefix}${quote}«masked»${quote}`;
  });
  return { text, masked };
}

