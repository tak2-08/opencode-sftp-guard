# OpenCode 1.18.22 API 실측 노트

작성·게시: **DSc (dsclub)** — DSc GitHub 계정(`tak2-08`)을 통해 게시.
작업 모델: **`space-bunny-free`** (모델 ID `opencode/space-bunny-free`)

이 문서는 **1.18.22 를 실제로 조사해서 얻은 사실**이다. 문서와 실제 동작이 다른 지점이 있어,
플러그인을 만들 때 필요한 사람이 시간을 아꼈으면 한다. 대상 환경: `opencode 1.18.22`.

---

## 0. 요약 — 플러그인 개발자가 가장 먼저 알아야 할 6가지

1. **기본 permission 은 `{"*":"allow"}`** → 커스텀 permission 의 `ask()` 는 기본 설정에서 통과한다.
2. **플러그인 로더는 한 단계만** 긊는다: `{plugin,plugins}/*.{ts,js}`. 보조 모듈을 `plugins/` 아래 두면 플러그인으로 오인된다.
3. **툴 반환값은 `string | {title?, output, metadata?}`** — 임의 객체를 반환하면 모델이 아무것도 못 본다.
4. **`ToolContext.ask({permission, patterns, always, metadata})`** — `always` 를 빈 배열로 주면 "Allow always" 가 무력화된다.
5. **`permission.reply("reject")` 는 같은 세션의 다른 대기 요청을 전부 실패**시킨다 → 세션별 직렬화가 필요하다.
6. **승인 다이얼로그는 알려진 permission 이름에만 본문을 렌더링**한다 — 커스텀 이름은 `Tool: <name>` 한 줄뿐.

---

## 1. permission 기본값과 `ask()` 의 함정 (가장 중요)

### 1.1 기본값

바이너리 내부의 기본 권한 규칙:

```js
{ "*": "allow",
  doom_loop: "ask",
  external_directory: { "*": "ask", <tmp/워크스페이스>: "allow" },
  question: "deny", plan_enter: "deny", plan_exit: "deny",
  read: { "*": "allow", "*.env": "ask", "*.env.*": "ask", "*.env.example": "allow" } }
```

`build` 에이전트는 여기에 `question: "allow", plan_enter: "allow"` 와 사용자 설정을 머지한다.

### 1.2 왜 커스텀 permission 의 ask 가 무효인가

`Permission.evaluate()` 는 규칙을 **평탄화한 뒤 `findLast`** 로 마지막 일치를 쓴다.

```ts
export function evaluate(permission, pattern, ...rulesets) {
  return rulesets.flat().findLast(
    (rule) => Wildcard.match(permission, rule.permission) && Wildcard.match(pattern, rule.pattern),
  ) ?? { action: "ask", permission, pattern: "*" }
}
```

`ask()` 는 이 결과가 `allow` 면 **질문 이벤트를 publish 하지 않고 그냥 성공**한다.
`"*": "allow"` 이라는 규칙이 배열 첫머리에 있으므로, `sftp_write` 같은 새 이름은
`question: "deny"` 같은 명시 규칙이 없으면 `*: allow` 에 걸려 통과한다.

→ **커스텀 permission 이름으로 게이트를 만들려면, 배포 설정에 그 이름의 `ask` 규칙이 반드시 있어야 한다.**
   그리고 그 규칙이 실려 있는지 **코드에서 확인**하는 수단이 필요하다(아래 1.4).

### 1.3 필요한 설정

`opencode.json`:

```json
{ "permission": { "sftp_write": "ask", "sftp_delete": "ask", "sftp_scope": "ask" } }
```

또는 **에이전트 frontmatter** (이 방식이 안전하다 — 다른 에이전트에 영향이 없다):

```yaml
---
tools: { sftp_read: true, sftp_write: true, bash: false, read: false, write: false }
permission:
  sftp_read: ask
  sftp_write: ask
---
```

frontmatter 는 `{agent,agents}/**/*.md` 에서 로드된다(`agents` 단수/복수 둘 다 인식).

### 1.4 게이트가 "살아 있는지" 확인하는 방법

`ask()` 는 질문 없이 통과할 수 있으므로, **질문 이벤트가 실제로 발생했는지**를 봐야 한다.
플러그인의 `event` 훅에서 `permission.asked` / `permission.replied` 를 받고,
`ask()` 가 끝난 뒤 관측 여부를 확인한다. 관측되지 않았으면 게이트 비활성 → DENY.

```ts
event: async ({ event }) => {
  if (event.type === "permission.asked")   /* 토큰 기록 */
  if (event.type === "permission.replied") /* 응답 기록 */
}
```

`ask()` 를 호출하는 쪽에서 `id` 를 직접 알 수 없으므로, **메타데이터에 상관 토큰을 심고
이벤트에서 되찾는** 방식이 필요하다. 토큰이 없으면 타임아웃 때 서버에 `reject` 를 보내
고아 요청을 정리할 수도 없다.

### 1.5 `--auto` 는 못 막는다

`--auto`(또는 TUI 의 auto 모드)는 `permission.asked` 를 받으면 **그대로 `once` 로 자동 응답**한다.
이벤트는 정상 발생하므로 1.4 의 검사로는 잡히지 않는다. 플러그인 안에서 구분할 방법이 없다.
→ `--auto` 없이 쓰도록 문서화하고, 게이트 생존을 확인할 자가 진단 툴을 제공한다.

---

## 2. 플러그인 로더

- 전역: `~/.config/opencode/plugins/`, 프로젝트: `.opencode/plugins/`
- 글롭: **`{plugin,plugins}/*.{ts,js}` — 한 단계만.** `dot: true` 포함.
- 보조 모듈을 `plugins/` 아래 두면 **각각 별도 플러그인으로 로드**된다(에러가 난다).
  → 진입점 하나만 `plugins/` 에 두고 구현은 다른 디렉터리로 뺀다.
- 로더는 프로젝트 디렉터리를 tsconfig 를 찾는다고 **가정한다**. 프로젝트 루트에
  `tsconfig.json` 이 없으면 플러그인 로드가 실패할 수 있다
  (`.opencode/sftp-guard/tsconfig.json` 은 그 폴더용이라 무관하지만, 루트에 하나 두는 편이 안전하다).
- 반환값: `Hooks` 객체. 사용 가능한 훅:
  `tool`(커스텀 툴) / `event` / `config` / `auth` / `provider` / `chat.message` /
  `chat.params` / `permission.ask` / `tool.execute.before` / `tool.execute.after` /
  `shell.env` / `experimental.session.compact*` / `dispose` 등.

### 2.1 `tool.execute.before` 를 게이트로 쓰지 말 것

`tool.execute.before(input, output)` 은 `input = { tool, sessionID, callID }`,
`output = { args }` 를 준다. 다만 **서브에이전트가 툴을 부를 때 항상 reliable 하지 않다**는
보고가 있어, 보안 게이트는 `execute()` 안에 두어야 한다. 훅은 방어심겹(예: 비밀 파일 읽기
차단)에만 쓴다.

---

## 3. 커스텀 툴 계약

```ts
import { tool } from "@opencode-ai/plugin"

export const MyPlugin: Plugin = async ({ client, project, directory, worktree, $ }) => ({
  tool: {
    my_tool: tool({
      description: "…",
      args: { path: tool.schema.string() },        // zod raw shape
      async execute(args, context) { … },           // context: ToolContext
    }),
  },
})
```

`ToolContext`:

| 필드 | 설명 |
|---|---|
| `sessionID`, `messageID`, `agent` | 호출 맥락. `agent` 는 permission 판단에 쓰인다 |
| `directory`, `worktree` | 로컬 경로. 상대 경로 해석에 쓴다(원격 작업이면 쓰지 않는다) |
| `abort` | `AbortSignal`. 중단 시 승인을 취소할 때 쓴다 |
| `metadata({ title, metadata })` | 진행 중 툴 카드 제목. **승인 전에 미리 채워 두면** 사람이 질문과 함께 본다 |
| `ask({ permission, patterns, always, metadata })` | 승인 요청. 질문 없으면 통과할 수 있음(§1) |

**반환값 계약(중요)**: `string` 또는 `{ title?, output, metadata?, attachments? }`.
임의 객체를 반환하면 모델에게 `output` 이 전달되지 않는다(도구가 성공처럼 보이지만 내용이 없다).

```ts
// 잘못됨
return { path, entries }
// 올바름
return { title: "…", output: "사람이 읽는 요약 문자열", metadata: { sftp: 정구조체 } }
```

### 3.1 `always: []` 로 "Allow always" 무력화

`reply("always")` 는 `input.always` 의 각 패턴을 `{ permission, pattern, action: "allow" }`
규칙으로 **영구 시드**한다. `always` 를 빈 배열로 넘기면 아무 규칙도 생기지 않아
"Allow always" 가 "Allow once" 와 동일하게 동작한다. 보안 게이트에는 유용한 기법이다.

### 3.2 TUI 승인 다이얼로그가 본문을 보여주는 경우

`edit` `read` `glob` `grep` `list` `bash` `task` `webfetch` `websearch` `external_directory`
`doom_loop` — 이 이름들에만 경로/명령/본문(`metadata.diff` 렌더)을 그린다.
그 외 이름은 `⚙ Permission required / Tool: <permission>` 한 줄만 나온다.
웹 UI 는 `settings.permissions.tool.<permission>.description` 과 `patterns` 를 추가로 보여준다.

→ 커스텀 permission 으로 사전 방지적 게이트를 만들면(기본 `allow` 회피) 미리보기는
`patterns` + 툴 카드 `title` + `metadata` 로 실어야 한다. `edit` 처럼 알려진 이름을
쓰면 본문 렌더를 얻지만 **기본값이 `allow` 라 게이트가 자동으로 꺼진다**(§1.2). 트레이드오프다.

---

## 4. 동시성

```ts
if (input.reply === "reject") {
  /* … 이 요청만 실패 … */
  for (const [id, item] of pending) {
    if (item.info.sessionID !== existing.info.sessionID) continue
    /* 같은 세션의 다른 대기 요청도 전부 reject */
  }
}
```

사람이 하나를 거부하면 **같은 세션의 다른 승인 요청이 전부 취소**된다.
여러 툴이 동시에 질문하면 서로를 죽인다 → 세션별 뮤텍스로 직렬화할 것.

---

## 5. SDK — 플러그인에서 쓸 수 있는 것

`PluginInput.client` 는 v1 클라이언트(`createOpencodeClient()`)다. 실제로 쓰는 범위:

| 호출 | 용도 |
|---|---|
| `client.app.log({ body: { service, level, message, extra } })` | 구조화 로그(권장). `console.log` 대신 |
| `client.session.create({ body: { parentID, title } })` | 자식 세션 생성(감사자용) |
| `client.session.prompt({ path:{id}, body:{ agent, system, tools, parts } })` | 서브에이전트 호출. `tools` 맵으로 툴을 on/off, `system` 으로 시스템 프롬프트 주입 |
| `client.session.delete({ path:{id} })` | 자식 세션 정리 |
| `client.postSessionIdPermissionsPermissionId({ path:{ id: sessionID, permissionID }, body:{ response } })` | 승인 요청에 서버 측 응답(타임아웃 정리용) |
| `client.config.get()` | 설정 조회 |

`body.tools` 로 호출 단위에서 툴을 끌 수 있다(에이전트 frontmatter 와 이중으로 막으면 안전).

> v2 SDK(`@opencode-ai/sdk/v2`)에는 `session.permission.*` 계열이 따로 보인다.
> v1 클라이언트 경로로 충분했으며, v2 로 갈아탈 이유는 없었다.

---

## 6. 문서 URL

- 플러그인: https://opencode.ai/docs/plugins/
- 권한: https://opencode.ai/docs/permissions/
- 에이전트: https://opencode.ai/docs/agents/
- 권한 규칙은 `permission: { tool: { pattern: action } }` 객체 문법이며,
  `*`/`?` 와일드카드, `~`/`$HOME` 확장, **마지막 일치가 이김**을 사용한다.

---

## 7. 이 프로젝트가 겪은 실제 함정 (재발 방지)

| 실수 | 증상 | 교훈 |
|---|---|---|
| `context.ask()` 만 믿음 | 아무 질문 없이 쓰기가 통과 | 항상 이벤트 관측으로 실측성 검증 |
| `always: ["*"]` | "항상 허용" 한 번으로 이후 전부 자동 통과 | 보안 게이트는 `always: []` |
| `plugins/` 아래에 모듈 배치 | 모듈이 플러그인으로 로드되어 충돌 | 구현은 다른 디렉터리로 |
| 임의 객체 반환 | 모델이 빈 결과를 봄 | `ToolResult` 계약 준수 |
| 동시 승인 요청 | 사람이 하나를 거부하자 나머지도 사라짐 | 세션별 직렬화 |
| 툴을 `tool.execute.before` 에서만 게이트 | 서브에이전트 경로에서 우제 | `execute()` 안에 넣기 |
