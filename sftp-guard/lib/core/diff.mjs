// 최소 unified diff — 승인 화면에 붙일 "내용 맥락"(§5).
// 외부 의존성 없이 구현한다(설치된 패키지를 늘리지 않기 위함).
// 전체 파일이 아니라 통계 + 잘라낸 hunks 만 보여준다: 프롬프트/트랜스크립트 폭주를 막는다.
import { humanBytes } from "./util.mjs";

/**
 * 라인 단위 LCS diff.
 * @param {string[]} a 이전
 * @param {string[]} b 이후
 * @returns {Array<{type: "eq"|"del"|"add", aIndex: number, bIndex: number, text: string}>}
 */
export function lineDiff(a, b) {
  //Guard: 매우 큰 파일은 LCS 를 하지 않는다(구현이 O(n*m)).
  const MAX = 20000;
  if (a.length > MAX || b.length > MAX) {
    return [
      ...a.map((text, i) => ({ type: "del", aIndex: i, bIndex: -1, text })),
      ...b.map((text, i) => ({ type: "add", aIndex: -1, bIndex: i, text })),
    ];
  }
  // 두 파일의 공통 접두/접미를 먼저 잘라내면 LCS 크기가 크게 줄어든다.
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);

  const ops = [];
  for (let i = 0; i < start; i++) ops.push({ type: "eq", aIndex: i, bIndex: i, text: a[i] });

  if (midA.length && midB.length) {
    const lcs = lcsTable(midA, midB);
    let i = 0;
    let j = 0;
    while (i < midA.length && j < midB.length) {
      if (midA[i] === midB[j]) {
        ops.push({ type: "eq", aIndex: start + i, bIndex: start + j, text: midA[i] });
        i++;
        j++;
      } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
        ops.push({ type: "del", aIndex: start + i, bIndex: -1, text: midA[i] });
        i++;
      } else {
        ops.push({ type: "add", aIndex: -1, bIndex: start + j, text: midB[j] });
        j++;
      }
    }
    while (i < midA.length) ops.push({ type: "del", aIndex: start + i++, bIndex: -1, text: midA[i - 1] });
    while (j < midB.length) ops.push({ type: "add", aIndex: -1, bIndex: start + j++, text: midB[j - 1] });
  } else {
    for (let i = 0; i < midA.length; i++) ops.push({ type: "del", aIndex: start + i, bIndex: -1, text: midA[i] });
    for (let j = 0; j < midB.length; j++) ops.push({ type: "add", aIndex: -1, bIndex: start + j, text: midB[j] });
  }

  for (let k = 0; k < a.length - endA; k++) {
    ops.push({ type: "eq", aIndex: endA + k, bIndex: endB + k, text: a[endA + k] });
  }
  return ops;
}

function lcsTable(a, b) {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const table = Array.from({ length: rows }, () => new Uint32Array(cols));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  return table;
}

/** Buffer/문자열 → 라인 배열(개행 정규화, 마지막 개행 유무 기록). */
export function toLines(input) {
  const text = Buffer.isBuffer(input) ? input.toString("utf8") : String(input ?? "");
  if (text === "") return { lines: [], endsWithNewline: true, hadCR: false };
  const hadCR = text.includes("\r");
  const norm = text.replace(/\r\n/g, "\n");
  const endsWithNewline = norm.endsWith("\n");
  const lines = norm.split("\n");
  if (endsWithNewline) lines.pop();
  return { lines, endsWithNewline, hadCR };
}

/**
 * 요약 통계 + hunks.
 * @param {Buffer|string} before
 * @param {Buffer|string} after
 * @param {{context?: number, maxHunks?: number, maxLines?: number}} [opts]
 */
export function buildDiff(before, after, opts = {}) {
  const context = opts.context ?? 3;
  const maxHunks = opts.maxHunks ?? 6;
  const maxLines = opts.maxLines ?? 240;
  const b = toLines(before);
  const a = toLines(after);
  const ops = lineDiff(b.lines, a.lines);

  let added = 0;
  let removed = 0;
  for (const op of ops) {
    if (op.type === "add") added++;
    else if (op.type === "del") removed++;
  }

  // hunk 만들기
  const changedIdx = [];
  ops.forEach((op, i) => {
    if (op.type !== "eq") changedIdx.push(i);
  });
  const hunks = [];
  const used = new Set();
  for (const idx of changedIdx) {
    if (hunks.length >= maxHunks) break;
    if (used.has(idx)) continue;
    const from = Math.max(0, idx - context);
    const to = Math.min(ops.length - 1, idx + context);
    const chunk = [];
    for (let i = from; i <= to; i++) {
      if (!used.has(i) && ops[i].type !== "eq") {
        for (let j = Math.max(0, i - context); j <= Math.min(ops.length - 1, i + context); j++) used.add(j);
      }
      chunk.push(ops[i]);
    }
    hunks.push(chunk);
  }

  const linesOut = [];
  let truncated = false;
  for (const hunk of hunks) {
    const first = hunk[0];
    const last = hunk[hunk.length - 1];
    linesOut.push(`@@ -${first.type === "add" ? first.bIndex + 1 : first.aIndex + 1},${hunk.length} @@`);
    for (const op of hunk) {
      if (linesOut.length >= maxLines) {
        truncated = true;
        break;
      }
      const prefix = op.type === "add" ? "+" : op.type === "del" ? "-" : " ";
      linesOut.push(`${prefix}${op.text}`);
    }
    if (truncated) break;
    void last;
  }
  const moreOps = changedIdx.length > hunks.length * (context * 2 + 1);

  return {
    added,
    removed,
    unchanged: ops.filter((o) => o.type === "eq").length,
    hunks,
    text: linesOut.join("\n"),
    truncated: truncated || moreOps,
    beforeBytes: byteLength(before),
    afterBytes: byteLength(after),
    binary: isBinaryish(before) || isBinaryish(after),
  };
}

function byteLength(x) {
  if (Buffer.isBuffer(x)) return x.length;
  return Buffer.byteLength(String(x ?? ""), "utf8");
}

function isBinaryish(x) {
  const buf = Buffer.isBuffer(x) ? x : Buffer.from(String(x ?? ""), "utf8");
  const limit = Math.min(buf.length, 2000);
  for (let i = 0; i < limit; i++) if (buf[i] === 0) return true;
  return false;
}

/** 사람이 읽는 한 줄 요약(로그/승인 패턴용). */
export function diffSummary(diff) {
  if (!diff) return "";
  if (diff.binary) return `binary payload ${humanBytes(diff.beforeBytes)} → ${humanBytes(diff.afterBytes)}`;
  return `+${diff.added} -${diff.removed} (변경 전 ${diff.unchanged}줄 유지, ${humanBytes(diff.beforeBytes)} → ${humanBytes(diff.afterBytes)})`;
}

/**
 * 정확한 문자열 교체(에이전트가 최소 변경을 하도록 지원).
 * find 는 기본적으로 정확히 한 번만 나타나야 한다(모호하면 거부 → 모델이 다시 읽게 만든다).
 * @returns {{ok: boolean, content?: string, applied?: number, reason?: string}}
 */
export function applyExactReplaces(content, edits) {
  let text = Buffer.isBuffer(content) ? content.toString("utf8") : String(content ?? "");
  const applied = [];
  for (const [i, edit] of (edits ?? []).entries()) {
    const find = String(edit?.find ?? "");
    const replace = String(edit?.replace ?? "");
    if (find === "") return { ok: false, reason: `edits[${i}].find 가 비어 있음` };
    const all = edit?.all === true;
    const count = countOccurrences(text, find);
    if (count === 0) return { ok: false, reason: `edits[${i}].find 가 현재 내용에 없음 (수정은 철회됨)` };
    if (!all && count > 1) {
      return { ok: false, reason: `edits[${i}].find 가 ${count}곳에 등장함 — all:true 를 명시하거나 더 긴 문맥을 넣을 것 (수정은 철회됨)` };
    }
    text = all ? text.split(find).join(replace) : text.replace(find, replace);
    applied.push({ index: i, replaced: all ? count : 1 });
  }
  return { ok: true, content: text, applied };
}

function countOccurrences(haystack, needle) {
  if (needle === "") return 0;
  let count = 0;
  let pos = 0;
  for (;;) {
    const idx = haystack.indexOf(needle, pos);
    if (idx === -1) break;
    count++;
    pos = idx + needle.length;
  }
  return count;
}
