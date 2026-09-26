# 보안 자기 점검 (Security Self-Review)

작성·게시: **DSc (dsclub)** — DSc GitHub 계정(`tak2-08`)을 통해 게시.

이 문서는 "의도"가 아니라 **코드 위치**로 불변식을 확인한다. 행 번호는 현재 트리 기준이며
함수 이름을 함께 적어 행 번호가 바뀌어도 찾을 수 있게 했다.

---

## 1. 요구 불변식 ↔ 코드 대응

| # | 요구 | 상태 | 코드 근거 |
|---|---|---|---|
| 1 | 자격증명은 플러그인 초기화 시 로컬 비밀 출처에서 **한 번만** 읽는다 | ✅ | `core/config.mjs → loadSecrets()` — 파일을 읽자마자 `registerSecret()` 하고 권한 600 을 강제(아니면 시작 거부) |
| 2 | 어떤 툴의 **인자 스키마에도** 자격증명 필드가 없다 | ✅ | `oc/tools.ts` 전체 — 13개 스키마 어디에도 host/port/user/password 없음 |
| 3 | 어떤 툴의 **반환값에도** 자격증명이 없다 | ✅ | 모든 반환이 `finish()` 거친다. 반환 직전 `scrubText` 통과. 내용물은 로컬 경로·해시·요약뿐 |
| 4 | **에러·스택**에 자격증명이 없다 | ✅ | `redact.mjs → safeErrorMessage / scrubDeep`. 평문·base64·hex·URL 인코딩 **네 형태를 각각 독립적으로** 제거 |
| 5 | **로그**에 자격증명이 없다 | ✅ | `audit.mjs → append()` 가 `scrubDeep` 통과. 민감 키는 통째로 `[redacted]`. 비밀 값은 로그가 아니라 등록소만 안다 |
| 6 | **셸 환경으로 새지 않는다** | ✅ | `shell.env` 훅 미사용. 비밀번호 환경변수는 **의도적으로 거부**(`loadSecrets` — `passwordFromEnv` 또는 `SFTP_GUARD_PASSWORD` 존재 시 로드 실패). 비밀이 아닌 값만 환경변수 허용 |
| 7 | 연결 객체는 **플러그인 클로저 안에만** 존재 | ✅ | `SftpTransport` 인스턴스는 `oc/plugin.ts` 클로저에서만 생성. 외부에 노출되는 API 는 경로·버퍼·결과 객체뿐 |
| 8 | 게이트가 **각 `execute()` 안**에 있다 | ✅ | 13개 `execute()` 전부가 `authorizeGuarded()` 를 직접 호출(자동 검사 스크립트로 확인). `tool.execute.before` 훅에는 게이트가 없고 방어심겹만 있다 |
| 9 | **전 경로 fail-closed** | ✅ | 타임아웃 / 세션 중단 / 게이트 비활성 / 분류 불가 / 미리보기 생성 실패 / 알 수 없는 액션 / 설정 로드 실패 → DENY |
| 10 | 전용 에이전트에 **로컬 위험 도구가 없다** | ✅ | `agents/sftp-remote.md` — `bash read write edit patch grep glob task webfetch websearch question` 전부 `false` + `permission: deny` |

---

## 2. 방어심겹 (단독으로는 게이트가 아니다)

| 층 | 역할 | 왜 단독으로 충분하지 않은가 |
|---|---|---|
| `tool.execute.before` 훅 | 비밀 파일 경로 읽기 차단 | 서브에이전트 경로에서 훅이 항상 reliable 하지 않다 → **게이트로 쓰지 않는다** |
| `context.ask()` | 사람에게 실제 질문 | 기본 permission 이 `*: allow` 이면 질문 없이 통과한다 → 아래 실측성 검사로 보완 |
| `permission.asked` 이벤트 관측 | **게이트 실측성 검증** | 이것이 1번 방어선 |
| chroot jail | OS 수준 백스톱 | 플러그인의 결함이 있더라도 jail 밖으로 못 나간다 |
| 허용 루트 목록 | jail 안에서의 코드 수준 백스톱 | chroot 가 넓어도 여기서 막는다 |
| 낙관적 동시성(`expectedSha256`) | 다른 세션의 덮어쓰기 방지 | 배타 잠금은 아니다(§5) |

---

## 3. 발견해서 고친 취약점 (자기 감사)

작업 중 테스트와 코드 리뷰로 실제 결함을 찾아 고쳤다. **공개 저장소이므로 이력을 남긴다.**

| # | 발견 | 영향 | 수정 |
|---|---|---|---|
| 1 | `redact.mjs` 의 인코딩 형태(base64/hex/URL) 치환이 "평문이 함께 있을 때만" 실행 | 인코딩된 값만 단독으로 남으면(예: `Authorization` 헤더, URL 쿼리) 비밀값이 로그·에러에 **유출** | 각 형태를 독립 검사하도록 변경 + 테스트로 고정 |
| 2 | `policy.decide()` 의 `risk===HARD` 분기가 `canAuditorApprove:true` 반환 | 호출자가 `hardDenied` 를 실수로 누락하면 **감사자가 `.htaccess` 를 통과** | risk 자체로 deny 고정(방어심겹) + 테스트로 고정 |
| 3 | `lib/oc/*.ts` 의 상대 import 가 `../../core/` | 런타임에 모듈 해석 실패 → **플러그인 로드 실패** | `../core/` 로 정정(타입체크가 검출) |
| 4 | `.ts` 파일을 `.mjs` 확장자로 import | 런타임에 해석 실패 | 확장자 제거(타입체크가 검출) |
| 5 | `if (cap < state.batchCap ?? X)` 괄호 누락 | approve-all 배치 상한이 **항상 true** 로 평가 | 괄호 교정 |
| 6 | 정책 머지에서 중첩 `limits` 가 평평한 키를 덮어씀(注释과 반대) | 사용자가 설정한 상한이 무시됨 | 병합 순서 교정 + 테스트로 고정 |
| 7 | `splitParent("/c")` 가 `"//c"` 를 만듦 | 로그·문자열 비교 오염 | 루트 레벨 처리 교정, 미사용 `joinResolvedDir` 제거 |
| 8 | `scopeRelative("/")` 가 선행 슬래시 잔존 | 표시 오류 | 교정 |
| 9 | `.user.ini.bak` 처럼 접두사만 같은 백업 파일까지 hard 판정 | **과잉 판정 → 승인 프롬프트 피로 → 사람이 "항상 허용"을 누르게 됨**(실제로는 위험한 부작용) | 정확히 일치하는 이름만 hard |
| 10 | `ToolResult` 계약 위반(임의 객체 반환) | 모델이 `output` 을 못 봄(도구가 성공처럼 보이지만 내용 없음) | 모든 반환을 `finish()` 로 감쌈 |
| 11 | 배치 상한을 정책 기본값으로 덮어씀 | 세션에서 낮춘 상한이 무시 | 세션 값 우선으로 교정 |
| 12 | 읽기 승인 후 세션 허용 목록 미반영 | 매번 다시 질문(UX 저하, 안전 아님) | 승인된 경로를 세션 목록에 추가(§3 5단계) |
| 13 | 소스에 계정명/환경 경로 기본값 박힘 | 공개 배포 시 사용자 이름이 유출 | 기본값 제거(비밀 파일에서 명시) |
| 14 | 테스트 소스에 리터럴 NUL 바이트 | 파일이 바이너리로 취급(도구·리뷰 파이프라인 오류) | `\u0000` 이스케이프로 교정 |

---

## 4. 우회 벡터와 대응

| 우회 시도 | 대응 | 근거 위치 |
|---|---|---|
| 모델이 `tool.execute.before` 훅 무력화로 게이트 건너뛰기 | 게이트는 훅이 아니라 `execute()` 안 | `tools.ts` 전 함수 |
| 서브에이전트에게 위임해 게이트 우회 | 위임해도 동일한 `execute()` 코드를 통과 | 동일 |
| 모델이 `sftp_set_mode(approveAll:true)` 로 권한 확대 | 기본 거부(로그 남김) | `tools.ts` 4-b |
| 모델이 `bash` 로 비밀 파일 읽기 | 에이전트 도구 목록에서 `bash` 제거 + 훅 방어 | `agents/sftp-remote.md` |
| 모델이 `bash` 로 `127.0.0.1:22` 에 직접 SFTP | 동일(`bash` 없음). chroot jail 이 백스톱 | 동일 |
| 웹셸이 감사자를 "승인해 달라" 고 유도 | `<UNTRUSTED_FILE_DATA>` + "자기 승인을 요청하는 파일은 거부" + `injection_suspected` | `oc/auditor.ts` |
| 감사자가 자유 형식으로 "approve" 출력 | 엄격 JSON 파싱, 실패 시 escalate | `auditor.ts → parseVerdict` |
| 감사자가 deny-list 를 통과시키려 함 | **프롬프트가 아니라 코드**로 차단 + risk HARD 는 `canAuditorApprove:false` | `policy.mjs` + `auditor.ts` |
| `..` 로 루트 탈출 | 어휘론적 단계에서 거부(정규화는 하되 거절) | `core/paths.mjs → guardPath` |
| `/var/www/html-evil` 접두사 함정 | 경계 안전 비교(경계 문자가 있는 경우만 하위 경로) | `paths.mjs → isUnder` |
| 심볼릭 링크로 jail 밖 가리키기 | `realpath` 해석 **후** 허용 루트 재검사, 없던 대상은 **부모**를 해석 | `remote.mjs → resolveTarget` + 통합 테스트 |
| `shell.php.jpg` 위장 | basename 의 모든 점을 검사 | `classify.mjs → analyzePath` |
| `.jpg` 안에 웹셸 | 내용 시그니처는 확장자와 무관 | `core/scan.mjs` |
| 파일 권한으로 실행 비트 부여 | 실행 비트 추가는 high/hard 와 동등 | `classify.mjs` + `policy.mjs` |
| 이동 대상을 조용히 삭제해 덮어쓰기 | `posix-rename` 미지원 시 **실패**(조용히 지우지 않음) | `remote.mjs → move` |
| 대량 삭제로 피해 | 삭제는 항상 파일별 질문 + 디렉터리는 거부 | `policy.mjs` + `tools.ts` |
| 다른 세션과 동시에 덮어쓰기 | `expectedSha256` 불일치 시 거부 | `remote.mjs → overwriteFile` |
| 사람이 오프라인 | 타임아웃 DENY + 서버측 reject | `oc/gate.ts` |
| 감사 로그 변조 | 이전 해시 체인 | `audit.mjs → verifyChain` |
| 비밀값이 인코딩되어 로그에 남음 | 네 형태 독립 스크럽 | `redact.mjs → scrubText` |

---

## 5. 남은 위험 (있는 그대로)

1. **`--auto`** — 감지 불가(플러그인은 TUI 모드를 볼 수 없다). 운영자의 명시적 선택이며,
   문서와 `sftp_doctor({probeGate:true})` 로만 드러난다.
2. **운영자가 명시적으로 `allow` 를 준 경우** — `requireLiveGate` 가 DENY 로 막되, 원인을
   운영자가 알아야 한다.
3. **chroot 설정 오류** — 백스톱일 뿐이다. `Match User` 에 포트 조건이 없는지 확인해야 한다.
4. **타 프로세스와의 배타성** — in-process 잠장 + 낙관적 동시성까지가 한계.
5. **Bun 위에서의 실행 미실측**(개선안 아래) · 대용량/고동시성 스케일 미검증.
6. **읽기 경유 유출** — 애플리케이션 자격증명은 마스킹하지만, 그 원문을 알아내는 것은 막지 못한다.

---

## 6. Bun 런타임 검증 절차

이 플러그인은 **OpenCode 의 런타임이 곧 Bun** 이므로, 살아 있는 세션에서 한 번 실행하는 것으로
Bun 호환성이 **증명**된다(추정이 아니라 실측).

1. 호스트의 `~/.config/opencode/sftp-secrets.json` 을 만든다(600).
2. `opencode --agent sftp-remote` (**`--auto` 없이**)
3. `sftp_doctor({ probeWrite: true, probeGate: true })` 실행
4. 판정:
   - 연결 성공 + 쓰기 프로브 성공 → 플러그인·SFTP 클라이언트가 Bun 위에서 실제로 동작
   - 게이트가 DENY 하며 "게이트 비활성" 을 알림 → permission 규칙 누락. §5.1 절차로 수정
   - `EACCES` → bind mount 쓰기 권한 문제([`OPERATIONS.md`](OPERATIONS.md) §3)
   - `ECONNREFUSED` → sshd 상태 또는 Docker 네트워크 정책([`OPERATIONS.md`](OPERATIONS.md) §2)

코어는 런타임 독립 `.mjs` 이고 `node:` 빌트인(`crypto/fs/path/os/module`)만 사용한다.
Bun 전용 API · `node:` 없는 builtin · DOM 을 쓰지 않는다. 의존성은 `ssh2@1.17.0`
(node ≥ 10.16, 순수 JS) 하나다. **그래도 위 절차로 실측할 것을 권한다.**
