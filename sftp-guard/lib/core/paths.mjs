// 경로 가드 — §7 "Path traversal via .., absolute paths, or symlinks".
//
// 3중 방어:
//   (1) 어휘론적(lexical) 정규화: `..`, `//`, `.`, 백슬래시, NUL 바이트 등을 제거/거부한다.
//       이 단계는 네트워크를 쓰지 않으므로 "존재 여부 확인 전"에도 항상 먼저 돈다.
//   (2) 허용 루트 경계 검사: allowedRoots 밖으로 나가는지(접두사 오탐 없이) 확인한다.
//   (3) 원격 realpath 해석 후 재검사: 심볼릭 링크를 실제로 따라가 jail/scope 밖이면 거부한다.
//       쓰기 대상처럼 아직 없는 파일은 "부모 디렉터리"를 해석해 붙인다(§7 symlink 우회 차단).
//
// 중요한 성질: 어떤 단계에서도 예외를 던지지 않고 {ok:false, reason} 을 돌려준다.
// 호출자는 fail-closed 로 처리해야 한다.
import { posixNormalize } from "./util.mjs";

/** 허용 루트 안에 들어 있는지(경계 안전 비교: /var/www/html-evil 은 /var/www/html 안이 아니다). */
export function isUnder(root, target) {
  const r = trimSlash(posixNormalize(root));
  const t = trimSlash(posixNormalize(target));
  if (r === "" || r === "/") return t.startsWith("/");
  if (t === r) return true;
  return t.startsWith(`${r}/`);
}

/** 루트 배열 중 하나에 들어 있으면 그 루트를, 아니면 null. */
export function whichRoot(roots, target) {
  for (const root of roots ?? []) {
    if (isUnder(root, target)) return trimSlash(posixNormalize(root));
  }
  return null;
}

/**
 * 어휘론적 경로 정규화. 이 단계만으로는 symlink 를 못 막는다(그래서 3단계가 필요하다).
 * @param {string} input 모델이 준 경로
 * @returns {{ok: boolean, path?: string, reason?: string, usedDotDot?: boolean}}
 */
export function normalizeLexical(input) {
  const raw = String(input ?? "");
  if (raw.length === 0) return { ok: false, reason: "빈 경로" };
  if (raw.includes("\0")) return { ok: false, reason: "NUL 바이트 포함 경로" };
  if (raw.length > 4096) return { ok: false, reason: "경로가 너무 김(4096자 초과)" };

  const unified = posixNormalize(raw);
  // 백슬래시를 슬래시로 바꿨다면, 원본에 역슬래시가 있었다는 사실을 기록한다(로그용).
  const isAbsolute = unified.startsWith("/");
  const segments = unified.split("/");
  const stack = [];
  let usedDotDot = false;
  for (const seg of segments) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      usedDotDot = true;
      // 루트 위로는 올라갈 수 없다. 정규화 결과로 확정하고 후속 단계에서 거부한다.
      stack.pop();
      continue;
    }
    stack.push(seg);
  }
  const normalized = `/${stack.join("/")}`;
  return { ok: true, path: normalized, usedDotDot, absolute: isAbsolute };
}

/**
 * 허용 루트 + discovery 루트 + scope 목록을 모두 고려한 접근 판정(어휘론적 단계).
 * @param {object} input
 * @param {string} input.path 정규화 전 경로
 * @param {string[]} input.allowedRoots chroot 안에서 허용된 두 루트(§0.1)
 * @returns {{ok: boolean, path?: string, root?: string, reason?: string}}
 */
export function guardPath(input) {
  const { path, ok, reason, usedDotDot } = normalizeLexical(input.path);
  if (!ok) return { ok: false, reason };
  if (usedDotDot) {
    // 정규화는 했지만, 모델이 `..` 을 쓴 사실 자체를 신뢰할 이유가 없다.
    return { ok: false, path, reason: "`..` 가 포함된 경로는 거부됨 (정규화 결과는 참고용: " + path + ")" };
  }
  const roots = input.allowedRoots ?? [];
  if (roots.length === 0) return { ok: false, path, reason: "허용 루트가 설정되지 않음(allowedRoots 비어 있음)" };
  const root = whichRoot(roots, path);
  if (!root) {
    return {
      ok: false,
      path,
      reason: `허용 루트 밖 경로: ${path} (허용: ${roots.join(", ")}) — §0.1 의 chroot 두 트리만 접근 가능`,
    };
  }
  return { ok: true, path, root };
}

/**
 * scope(승인된 경로 목록) 안인지 판정.
 * 항목은 정확한 파일 경로이거나 디렉터리 접두사다. 접두사 비교는 경계 안전해야 한다.
 * @param {string[]} scopePaths
 * @param {string} target
 * @returns {{inScope: boolean, matched?: string}}
 */
export function matchScope(scopePaths, target) {
  const t = trimSlash(posixNormalize(target));
  let best = null;
  for (const raw of scopePaths ?? []) {
    const s = trimSlash(posixNormalize(raw));
    if (s === "" || s === "/") return { inScope: true, matched: s || "/" };
    if (t === s) return { inScope: true, matched: s };
    if (t.startsWith(`${s}/`)) {
      if (!best || s.length > best.length) best = s; // 가장 좁은 매치를 기록
    }
  }
  return best ? { inScope: true, matched: best } : { inScope: false };
}

/**
 * scope 안의 "상대 경로" 를 계산(로그/감사자에게 보여줄 경로축약용).
 * @returns {string|null}
 */
export function scopeRelative(matched, target) {
  if (!matched) return null;
  const t = trimSlash(posixNormalize(target));
  const m = trimSlash(posixNormalize(matched));
  if (m === "/" || m === "") return t.replace(/^\/+/, "");
  return t.startsWith(`${m}/`) ? t.slice(m.length + 1) : t;
}

/**
 * 경로를 부모 디렉터리와 basename 으로 나눈다.
 * 원격 해석 순서(§7 symlink 우회 차단):
 *   1) 대상 전체를 realpath 시도한다. 있으면 그것이 최종 경로다.
 *   2) 없으면(생성 대상) 부모 디렉터리를 realpath 하고 basename 을 붙인다.
 *      → 심볼릭 링크로 다른 트리에서 같은 이름이 보이는 경우를 잡는다.
 * @param {string} normalizedPath
 * @returns {{dir: string, base: string, parent: string}}
 */
export function splitParent(normalizedPath) {
  const trimmed = trimSlash(normalizedPath);
  if (!trimmed.includes("/")) return { dir: "/", base: trimmed, parent: `/${trimmed}` };
  const idx = trimmed.lastIndexOf("/");
  const dir = idx === 0 ? "/" : trimmed.slice(0, idx);
  const base = trimmed.slice(idx + 1);
  return { dir, base, parent: `${dir === "/" ? "" : dir}/${base}` };
}

/** 경로 조각 목록(로그/미리보기용). */
export function pathSegments(p) {
  return posixNormalize(p).split("/").filter(Boolean);
}

function trimSlash(p) {
  const s = String(p ?? "");
  if (s === "/") return "/";
  return s.replace(/\/+$/, "");
}
