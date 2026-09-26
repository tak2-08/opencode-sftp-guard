#!/usr/bin/env bash
# sftp-guard 설치 스크립트.
#
# 이 저장소의 디렉터리 구조는 opencode 설정 디렉터리(.opencode 또는 ~/.config/opencode)를
# 그대로 미러링한다. 그래서 "복사"만 하면 상대 경로 import 가 그대로 성립한다
# (plugins/sftp-guard.ts → ../sftp-guard/lib/oc/plugin).
#
#   plugins/sftp-guard.ts   → <opencode-config>/plugins/sftp-guard.ts
#   sftp-guard/             → <opencode-config>/sftp-guard/
#   agents/*.md             → <opencode-config>/agents/
#   package.json            → <opencode-config>/package.json  (의존성 "병합"만 하고 덮어쓰지 않는다)
#
# 사용법:
#   ./install.sh              # 기본: ~/.config/opencode
#   ./install.sh /path/to/cfg # 다른 설정 디렉터리
#   DRY_RUN=1 ./install.sh    # 실제 복사 없이 무엇을 할지만 출력
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-$HOME/.config/opencode}"
DRY_RUN="${DRY_RUN:-0}"

say()  { printf '%s\n' "$*"; }
step() { say ""; say "▸ $*"; }
run()  { if [ "$DRY_RUN" = "1" ]; then say "  (dry-run) $*"; else "$@"; fi; }

step "설치 대상 확인"
say "  저장소:   $REPO_ROOT"
say "  대상 경로: $TARGET"
if [ ! -d "$TARGET" ]; then
  say "  대상 디렉터리가 없다 — 새로 만든다"
  run mkdir -p "$TARGET"
fi

step "1) 플러그인 진입점"
run mkdir -p "$TARGET/plugins"
run cp "$REPO_ROOT/plugins/sftp-guard.ts" "$TARGET/plugins/sftp-guard.ts"
say "  → $TARGET/plugins/sftp-guard.ts"

step "2) 구현(코어 + 오픈코드 결합부 + 테스트)"
run mkdir -p "$TARGET/sftp-guard"
# node_modules 는 복사하지 않는다(의존성은 opencode 가 시작 시점에 설치한다).
run cp -R "$REPO_ROOT/sftp-guard/." "$TARGET/sftp-guard/"
say "  → $TARGET/sftp-guard/"

step "3) 에이전트 정의"
run mkdir -p "$TARGET/agents"
run cp "$REPO_ROOT/agents/sftp-remote.md" "$TARGET/agents/sftp-remote.md"
run cp "$REPO_ROOT/agents/risk-auditor.md" "$TARGET/agents/risk-auditor.md"
say "  → $TARGET/agents/{sftp-remote,risk-auditor}.md"

step "4) 의존성 병합(기존 package.json 을 덮어쓰지 않는다)"
if [ "$DRY_RUN" = "1" ]; then
  say "  (dry-run) $TARGET/package.json 에 ssh2-sftp-client@12.1.1 병합"
elif [ -f "$TARGET/package.json" ]; then
  node -e '
    const fs = require("fs");
    const p = process.argv[1];
    const pkg = JSON.parse(fs.readFileSync(p, "utf8"));
    pkg.dependencies = pkg.dependencies || {};
    pkg.dependencies["ssh2-sftp-client"] = "12.1.1";
    fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + "\n");
    console.log("  → ssh2-sftp-client 병합 완료");
  ' "$TARGET/package.json"
else
  run cp "$REPO_ROOT/package.json" "$TARGET/package.json"
  say "  → $TARGET/package.json (신규 생성)"
fi

step "5) 비밀 파일(저장소 밖, 권한 600) — 지금은 만들지 않는다"
say "  cp sftp-guard/sftp-secrets.example.json $TARGET/sftp-secrets.json"
say "  \$EDITOR $TARGET/sftp-secrets.json   # host/port/username/password 입력"
say "  chmod 600 $TARGET/sftp-secrets.json"
say "  (선택) cp sftp-guard/sftp-guard.config.example.json $TARGET/sftp-guard.json"

step "완료"
say "  1) opencode 를 재시작한다"
say "  2) --auto 없이 실행한다:"
say "       opencode --agent sftp-remote"
say "  3) 첫 세션에서 연결 상태를 확인한다:"
say "       sftp_doctor({ probeWrite: true, probeGate: true })"
say ""
say "  게이트가 실제로 뜨는지 반드시 확인하세요. 기본 permission 은 '\"*\": \"allow\"' 이므로"
say "  sftp_* 규칙이 없으면 플러그인이 스스로 '게이트 비활성' 으로 판단해 쓰기를 거부합니다(그것이 정상입니다)."
