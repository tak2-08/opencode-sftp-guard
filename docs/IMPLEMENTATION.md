# 구현 상세 (Implementation Notes)

작성·게시: **DSc (dsclub)** — DSc GitHub 계정(`tak2-08`)을 통해 게시.
작업 모델: **`space-bunny-free`** (모델 ID `opencode/space-bunny-free`)

코드를 읽기 전에 이 문서를 읽으면 각 모듈이 **왜 그렇게** 되어 있는지 이해할 수 있다.
줄 번호는 현재 트리 기준(함수 이름 병기).

---

## 1. 레이어 구조와 그 이유

```
lib/core/*.mjs   런타임 독립 계층 — opencode 를 전혀 모른다
lib/oc/*.ts      오픈코드 결합 계층 — 게이트, 감사자, 툴, 훅
```

**왜 이렇게 나눴나.** 코어가 `client` 나 `ToolContext` 를 알면, 코어를 직접 로드하는
테스트 하네스가 opencode 없이서는 못 돌아간다. 그럼 보안 로직(분류기·경로 가드·무결성 검증)을
실제 SFTP 통신과 함께 검증할 수 없다. 분리를 유지한 결과로:

- `lib/core` 는 **Node 20 에서 132개 테스트가 돈다**(실제 in-process SFTP 서버 포함).
- 같은 파일이 Bun(OpenCode 런타임)에서도 그대로 실행된다. 런타임 분기 코드가 없다.

`lib/core` 는 순수 Node 빌트인(`node:crypto`, `node:fs`, `node:path`, `node:os`, `node:module`)만 쓴다.
Bun 전용 API · `node:` 없는 builtin · DOM 을 쓰지 않는다.

---

## 2. 데이터 흐름 — 쓰기 한 번의 전체 경로

` sftp_edit_existing ` 예시:

```
① execute(args, context)
   ├─ content / edits 중 정확히 하나 검증
   │
② resolveOrThrow(ctx, context, path)
   └─ transport.resolveTarget(path)                    core/remote.mjs:183
      ├─ (1) guardPath — 어휘론적 정규화 + `..` 거부 + 허용 루트 경계   core/paths.mjs:69
      ├─ (2) ensureConnected — 지연 연결(재시도 포함)                  core/remote.mjs:75
      ├─ (3) realpath(대상) → 있으면 그 경로 / 없으면 realpath(부모)   core/remote.mjs:236
      └─ (4) 해석 결과가 허용 루트 안인가 재검사  ← 심볼릭 링크 탈출 차단
   │
③ 기존 내용 읽기 + sha256 계산 (낙관적 동시성의 기준선)
   └─ args.expectedSha256 가 있으면 지금 해시와 비교 → 다르면 즉시 거부
   │
④ 새 내용 계산 (전체 교체 또는 applyExactReplaces)
   └─ find 가 0곳/2곳 이상이면 거부(모호한 수정은 하지 않는다)
   │
⑤ classifyTarget(path, content, existingContent)        core/classify.mjs
   └─ high / hard / static
   │
⑥ buildDiff(before, after) → buildWritePreview()          core/policy.mjs:261
   │
⑦ authorizeGuarded(...)                                   oc/tools.ts:80
   ├─ decide(action, target, classification, hardDenied, session, policy)   core/policy.mjs:56
   ├─ DENY  → 감사 로그 + throw            (게이트로 승인 불가)
   ├─ ALLOW → 감사 로그(scope-auto | approve-all) 후 통과
   └─ ASK
      ├─ canAuditorApprove && 감사자 모드 → runAuditor()      oc/auditor.ts
      │    ├─ 판정 불가/deny →人类로 fallback
      │    └─ approve → 감사 로그 후 통과
      └─ 그렇지 않으면 gate.requestHumanApproval()            oc/gate.ts:109
           ├─ 세션 뮤텍스(동시 요청 직렬화)
           ├─ context.metadata(title) → context.ask(...)
           ├─ 타임아웃 / abort → DENY + 서버측 reject
           ├─ 실측성 검증(#confirmLiveness) → 이벤트 없으면 DENY   oc/gate.ts:245
           └─ 승인 → 감사 로그 후 통과
   │
⑧ withPathLock(resolvedPath, …)                          core/remote.mjs
   └─ overwriteFile(path, next, mode, { expectedSha256, backup })   core/remote.mjs:372
      ├─ (동시성) 현재 해시가 기대값과 다르면 거부
      ├─ put(flags "w")
      ├─ verifyWritten — stat 크기 + 재읽기 sha256 대조     core/remote.mjs:412
      └─ 검증 실패 && backup 있음 → backup 으로 롤백
   │
⑨ audit.append(outcome, hashes, diff 요약) + 모델 반환
```

**게이트는 ⑦ 한 곳에만 있고, 그것을 부르는 것은 `execute()` 이다.**
훅(`tool.execute.before`)은 방어심겹(비밀 파일 읽기 차단)일 뿐이다.

---

## 3. 경로 가드 — 3중 방어 (`core/paths.mjs`, `core/remote.mjs:183`)

모델이 준 경로가 jail 밖으로 나갈 수 있는 경로는 세 가지다. 각각 따로 막는다.

### (1) 어휘론적 — `guardPath` (paths.mjs:69)

- 백슬래시 → 슬래시, `//` 축약, `.` 제거, NUL 바이트 거부, 길이 4096 초과 거부
- **`..` 가 하나라도 있으면 정규화하되 거절한다.** 정규화 결과를 함께 보여주되 통과시키지 않는다
  ("정규화했으니 안전하다" 는 오판을 막기 위해).
- 허용 루트 경계 비교(`isUnder`, paths.mjs:15)는 **경계 문자가 있는 경우만** 하위 경로로 인정한다:

  ```
  isUnder("/var/www/html", "/var/www/html/a")      → true
  isUnder("/var/www/html", "/var/www/html-evil/x")  → false   ← 접두사 함정
  ```

### (2) 허용 루트 목록

`allowedRoots` 밖은 네트워크 호출 전에 거부된다. chroot 가 넓어도 여기서 막는다.

### (3) 원격 `realpath` 해석 후 재검사 — 심볼릭 링크

SFTP `realpath` 는 서버가 실제로 따라간 경로를 준다. 두 경우를 나눠 처리한다.

| 대상 | 처리 | 이유 |
|---|---|---|
| **존재하는 경로** | 그 경로 자체를 `realpath` | 링크가 가리키는 실제 위치가 나온다 |
| **존재하지 않는 경로**(생성 대상) | **부모 디렉터리**를 `realpath` 하고 basename 을 붙인다 | `/jail/link/newfile` 에서 `link` 가 jail 밖을 가리키는 경우를 잡아야 하기 때문 |

그 뒤 해석 결과가 `allowedRoots` 안인지 다시 확인한다. 이 단계는
`test/integration.test.mjs` 에서 실제 파일시스템의 심볼릭 링크로 검증한다(디렉터리 링크·파일 링크 모두).

### 3.1 `matchScope` — 승인 범위 매칭

범위 항목은 **정확한 경로 또는 디렉터리 접두사**다. 접두사 비교는 경계 안전하며,
여러 항목이 걸리면 **가장 좁은 것**을 기록한다(로그에 정확한 근거를 남기기 위해).

---

## 4. 위험 분류 (`core/scan.mjs`, `core/classify.mjs`)

### 4.1 내용 시그니처 3단계

| 단계 | 판정 | 예시 |
|---|---|---|
| **hard** | 단독으로 웹셸 확정 | `<?php` / ASP 태그 / `$_GET[...]` 를 코드 위치에 쓰는 형태 / `preg_replace('/…/e')` / `assert('…')` / `create_function(` |
| **suspect** | 단독으론 확정 아님, 그러나 high 로 승격 | `eval(` `system(` `exec(` `shell_exec(` `passthru(` `proc_open(` `popen(` `base64_decode(` `gzinflate(` `str_rot13(` … |
| **난독화 흔적** | 가산점 | 긴 16진/유니코드 이스케이프, 긴 base64 덩어리, `chr()` 문자열 조립 |

- 본문은 확장자와 무관하게 UTF-8 로 해석해 검사한다(NUL 로 중단하지 않는다).
- 검사 상한(기본 4 MiB)을 넘으면 "일부만 검사됨" 을 결과에 명시한다(조용히 통과시키지 않는다).

### 4.2 경로 분석

- basename 의 **모든 점(.)** 으로 쪼개 모든 조각을 확장자 후보로 본다 → `shell.php.jpg` 검출.
- 웹서버가 실제로 읽는 설정 파일은 **정확히 일치하는 이름**으로만 hard 판정한다.
  접두사 규칙을 넓히면(`.user.ini.bak` 등) 승인 프롬프트 피로가 생겨 결국 사람이
  "항상 허용"을 누르게 되는 역효과가 생긴다. **과잉 판정도 보안 결함이다.**

### 4.3 deny-list (`isHardDeniedTarget`)

- `risk === hard`
- 웹셸 하드 시그니처 보유
- 자격증명/설정 파일명(`.env*`, `wp-config*`, `id_rsa*`, `.htpasswd` …)
- 경로 조각에 민감 토큰(`auth`, `session`, `credential`, `payment`, `token`, `key` …)

deny-list 는 **감사자 verdict 를 이길 수 없다**(`oc/auditor.ts`). 그리고 `decide()` 도
`risk === hard` 를 `canAuditorApprove: false` 로 고정한다 — 호출자가 `hardDenied` 를
실수로 빠뜨려도 막히는 방어심겹이다.

---

## 5. 승인 게이트 (`oc/gate.ts`)

### 5.1 왜 세션 뮤텍스가 있는가

OpenCode 의 reject 는 같은 세션의 대기 요청을 전부 실패시킨다
([`OPENCODE-API-NOTES.md`](OPENCODE-API-NOTES.md) §4). 병렬 질문이 서로를 취소하지 않도록
세션 단위 큐를 둔다. 게이트 외의 요청(내장 edit 툴 등)과는_opencode 내부에서_ 직렬화되지
않으므로, 그것까지 고려하진 못한다(§5.5 남은 위험).

### 5.2 상관 토큰

`ask()` 는 요청 id 를 돌려주지 않는다. timeout 에 그 id 로 `reject` 보내려면,
`ask()` 호출 전에 고유 토큰을 만들어 `metadata.sftpGuardToken` 에 심고,
이벤트 훅이 `permission.asked` 를 받을 때 토큰으로 되찾는다. 그러면

- **실측성**: 토큰의 이벤트가 없으면 게이트 비활성 → DENY
- **정리**: 타임아웃 시 `pending` 에 기록된 id 로 `postSessionIdPermissionsPermissionId(response:"reject")`

### 5.3 실측성 판정(`#confirmLiveness`, gate.ts:245)

`ask()` 가 끝난 뒤 최대 2초 동안 이벤트를 기다린다.

| 관찰 | 판정 |
|---|---|
| 토큰 이벤트 관찰 | `live` → 승인 인정 |
| `requireLiveGate: false` | `live` (운영자가 검사를 끈 경우) |
| `repliedAt > 0` 인데 `asked` 를 못 봄 | `live` (훅 부분 실패 — 이벤트 훅은 살아 있음) |
| 어떤 이벤트도 없음 | `dead` → **DENY** + 필요한 설정 줄을 오류 메시지에 포함 |
| 시간 초과 + 일부 이벤트만 | `unknown` → **DENY** (fail closed) |

### 5.4 타임아웃·중단

`ask()` 를 `setTimeout`(기본 10분)과 `context.abort` 중races로 감싼다.
둘 중 먼저 오는 쪽이 DENY 를 결정하고, 남은 요청은 서버에 `reject` 한다.
→ 사람이 오프라인이어도 세션이 영원히 뜨지 않는다.

### 5.5 "Allow always" 무력화

`always: []` 를 넘긴다. OpenCode 의 "Allow always" 응답은 `always` 패턴을 `allow` 규칙으로
영구 시드하는데, 배열이 비면 아무것도 시드되지 않아 "Allow once" 와 동일하게 동작한다.
범위 확대는 `sftp_request_scope_approval` 과 `sftp_set_mode` 경로로만 열리고, 그 둘도 게이트를 거친다.

---

## 6. 전송 계층 무결성 (`core/remote.mjs`)

### 6.1 "에러가 안 났으면 성공" 은 믿지 않는다

```ts
put(buffer, path, { flags: "wx" | "w" })
→ verifyWritten(path, content)      core/remote.mjs:412
   ├─ stat 으로 크기 대조   (다르면 "부분 기록" 으로 실패)
   └─ get 으로 재읽기 → sha256 대조 (다르면 "원격 손상/중간 변경" 으로 실패)
```

- `writeNewFile` 은 `flags: "wx"` 로 **원자적 no-clobber** — 이미 있으면 서버가 실패시킨다.
- `overwriteFile` 은 검증 실패 시 `backup` 이 있으면 **되돌린다**(`rolledBack: true` 로 보고).
- 중간에 연결이 끊기면 `put` 자체가 실패하거나 `verifyWritten` 이 크기 불일치를 잡는다
  (통합 테스트에서 200KB 전송 중 채널 파괴로 재현).

### 6.2 낙관적 동시성

`overwriteFile(path, next, mode, { expectedSha256 })`:

1. 현재 원격 해시를 읽어 기대값과 비교.
2. 다르면 **덮어쓰지 않고** 어느 쪽이 최신인지 알려주며 실패시킨다.

`expectedSha256` 는 모델이 `sftp_read` 때 받은 해시를 넘기는 방식이라, "읽은 뒤로 다른 사람이
수정했다" 는 경우를 잡는다. 단, `put` 과 검증 사이의 좁은 창은 남는다(배타 잠장이 아님).

### 6.3 경로별 직렬화

`withPathLock(key, fn)` 은 같은 키의 호출을 직렬화한다(프로세스 내).
테스트는 5개 병렬 호출의 진입/종료가 겹치지 않음을 확인한다.

### 6.4 이동(오버라이트 안전)

```
대상 없음 → posixRename → 실패하면 rename
대장 있음 + overwrite:true → posixRename
   └─ 미지원 서버면 "조용히 지우고" 하지 않고 실패시킨다
```

`verify` 로 출발지 소멸과 도착지 존재를 확인한다.

### 6.5 오류 표면화

원격 오류를 `EACCES`/`EPERM`/`EHOSTUNREACH`/`ECONNREFUSED` 등 코드별로 사람이 읽을 문장으로
바꾼다. 권한 거부일 때는 **계정이 경로 소유 그룹에 속해야 한다**는 원인과 확인 방법을 함께 준다.
에러 메시지는 전부 `redact` 를 통과한다.

---

## 7. 감사 로그 해시 체인 (`core/audit.mjs:32`)

```jsonc
{ "ts": "…", "tool": "sftp_write_new", "action": "write_new",
  "requested": "/var/www/html/x.php", "resolved": "/var/www/html/x.php",
  "scopeRelative": "x.php",                    // 어떤 scope 항목에 붙는지
  "risk": "hard", "classification": "HARD-DENY: …",
  "outcome": "human-approved", "approver": "human",
  "beforeSha256": "…", "afterSha256": "…", "size": 1234,
  "diffSummary": "+3 -1 (변경 전 20줄 유지, 1.2 KiB → 1.4 KiB)",
  "prev": "<이전 항목의 hash>", "hash": "<sha256(prev + 본문)>" }
```

- 항목마다 `scrubDeep` 통과 → **비밀값이 기록될 수 없다.**
- `prev`/`hash` 체인으로 줄 삭제·삽입·변조가 감지된다(`verifyChain()`).
- 로테이션: `audit.log` → `.1` → `.2` → `.3` (용량 상한 5 MiB).
- **로깅 실패는 작업을 막지 않는다.** 감사 로그를 못 쓴다고 파일 쓰기가 실패하면 안 된다.
- 본문은 담지 않는다(diff 요약과 해시만). 본문 excerpt 가 필요하면 호출부에 한 줄 추가.

---

## 8. 상태 관리

| 상태 | 수명 | 위치 |
|---|---|---|
| 승인 범위(`scopePaths`) | **세션** (메모리 전용, 디스크에 안 씀) | `SessionState` (`oc/tools.ts:19`) |
| 탐색 루트(`discoveryRoot`) | 세션 | 동일 |
| approve-all / 자동 허용 누적 카운트 | 세션 (`sftp_set_mode` 로 초기화) | 동일 |
| 감사자 재시도 카운트 | 세션+대상경로 | 동일 |
| 게이트 통계 / 실측성 관측 여부 | 프로세스 | `ApprovalGate` |
| 연결 객체 | 프로세스 (클로저) | `SftpTransport` |

세션은 32개를 넘으면 오래된 것부터 정리하고, `session.deleted` 이벤트 시 즉시 제거한다.

---

## 9. 초기화 실패 처리

설정/비밀 로딩은 플러그인 진입 시 1회. 실패하면 **도구가 사라지는 게 아니라 모든 `sftp_*` 툴이
명시적으로 실패**하는 플러그인으로 교체된다(`oc/plugin.ts → createDisabledPlugin`).
`opencode.json` 을 손대지 않으려고(사용자의 확고한 금지 규칙) 설정 파일로만 바꾼다.
