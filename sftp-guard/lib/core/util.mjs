// 공통 유틸리티 — 런타임 독립(runtime-agnostic) 계층.
// 이 파일은 Node(테스트 하네스)와 Bun(opencode 런타임) 양쪽에서 그대로 실행되어야 한다.
// Node 전용 API, Bun 전용 API, DOM API 를 쓰지 않는다.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** SHA-256 hex digest. Buffer/string 모두 허용. */
export function sha256(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
  return createHash("sha256").update(buf).digest("hex");
}

/** 짧은 해시(로그·미리보기용). */
export function shortHash(data, len = 12) {
  return sha256(data).slice(0, len);
}

/** 충돌 가능성이 무시할한 난수 토큰(승인 요청 상관관계용). */
export function randomToken(bytes = 12) {
  return randomBytes(bytes).toString("hex");
}

/** 상수 시간 문자열 비교(경로 비교 등 timing 차이로 정보가 새지 않게). */
export function safeEqual(a, b) {
  const ba = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  if (ba.length !== bb.length) {
    // 길이가 다르면 timingSafeEqual 은 쓸 수 없다. 그래도 상수 시간에 가깝게 비교한다.
    let diff = ba.length ^ bb.length;
    const n = Math.max(ba.length, bb.length);
    for (let i = 0; i < n; i++) diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 값이 숫자/유한수면 숫자로, 아니면 fallback 을 돌려준다(설정 스키마 검증용). */
export function asNumber(value, fallback) {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

export function asBool(value, fallback) {
  if (value === true || value === "true" || value === 1 || value === "1") return true;
  if (value === false || value === "false" || value === 0 || value === "0") return false;
  return fallback;
}

export function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

/** 문자열을 지정 바이트 수로 자르되 UTF-8 경계를 깨지 않게 한다. */
export function truncateBytes(str, maxBytes) {
  const buf = Buffer.from(String(str), "utf8");
  if (buf.length <= maxBytes) return { text: buf.toString("utf8"), truncated: false, bytes: buf.length };
  // 뒤에서 0x80~0xBF(연속 바이트)를 잘라내 UTF-8 시퀀스가 깨지지 않게 한다.
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return { text: buf.subarray(0, end).toString("utf8"), truncated: true, bytes: buf.length };
}

/** 사람이 읽는 바이트 수 표기. */
export function humanBytes(n) {
  if (!Number.isFinite(n)) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}

/** 단일 줄로 압축(로그용). 제어문자는 이스케이프한다. */
export function oneLine(str, max = 400) {
  const flat = String(str ?? "")
    // 제어문자는 정규식 이스케이프로만 제거한다.
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s*\n+\s*/g, " ")
    .trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

/** Buffer 가 텍스트로 안전하게 해석 가능한지(UTF-8 검증). */
export function isValidUtf8(buf) {
  if (Buffer.isBuffer(buf)) {
    // TextDecoder 의 fatal 모드가 가장 정확한 판정이다.
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(buf);
      return true;
    } catch {
      return false;
    }
  }
  return true;
}

/** 바이너리 heuristic: NUL 바이트가 있거나 UTF-8 로 해석 불가하면 바이너리. */
export function looksBinary(buf) {
  if (!Buffer.isBuffer(buf)) return false;
  const limit = Math.min(buf.length, 8000);
  for (let i = 0; i < limit; i++) if (buf[i] === 0) return true;
  return !isValidUtf8(buf.subarray(0, limit));
}

/** ISO-8859-1 등 라벨이붙은 문자열이라도 깨지 않게 latin1 로 되돌린다(보수적). */
export function decodeLatin1(buf) {
  return Buffer.isBuffer(buf) ? buf.toString("latin1") : String(buf);
}

/** deep clone-ish(설정 객체 병합용). JSON round-trip 은 Date 등을 잃으므로 직접 복사. */
export function shallowMerge(base, override) {
  const out = { ...base };
  for (const [k, v] of Object.entries(override ?? {})) {
    if (v === undefined) continue;
    out[k] = v;
  }
  return out;
}

/** 배열/객체를 동적으로 생성하는 최소 헬퍼. */
export function unique(list) {
  return Array.from(new Set(list));
}

/** ISO-8601 UTC 타임스탬프(로그용). */
export function nowIso() {
  return new Date().toISOString();
}

/** 경로 구분자 정규화(원격은 POSIX 가정). */
export function posixNormalize(p) {
  return String(p ?? "").replace(/\\/g, "/");
}
