# 운영 (Operations)

작성·게시: **DSc (dsclub)** — DSc GitHub 계정(`tak2-08`)을 통해 게시.

설치 후 실제로 손봐야 하는 지점과, 문제가 났을 때의 진단 순서를 모은다.

---

## 1. 토폴로지 — 왜 루프백인가

```
┌─────────────────────────────┐        ┌────────────────────────────────┐
│ Docker 컨테이너            │        │ 호스트                          │
│  opencode (Bun)            │        │  sshd :22                      │
│   └ sftp-guard             │        │   └ Match User <sftp-user>     │
│      SftpTransport ────────┼─127.0.0.1:22─┤  ChrootDirectory /srv/sftp-jail│
└─────────────────────────────┘  loopback└───────────────────────────────┘
```

- 컨테이너와 대상 파일이 **같은 물리 호스트**에 있으므로, SFTP 는 **컨테이너 → 호스트 루프백 홉**이다.
- **공개 도메인 / DDNS / 포트 포워딩 경로는 필요도 의존도도 아니다.** 그 경로는 사람이
  외부에서 테스트할 때만 쓰던 것이고, 플러그인 자신의 SFTP 호출과는 무관하다.
- `host.docker.internal` 이 필요한 배치(맥/리눅스, host-gateway 미설정)에서는
  비밀 파일의 `host` 만 바꾸면 된다. **코드 변경은 불필요하다.**

---

## 2. Docker 네트워크가 호스트 포트를 막는 경우

일부 샌드박스는 의도적으로 호스트 접근을 기본 차단한다. 확인·조치 순서:

```bash
# 1) 호스트에서 sshd 가 루프백에서 listening 하는가
ss -ltnp | grep ':22 '

# 2) 컨테이너에서 실제로 닿는가
docker exec -it <container> sh -c 'nc -vz 127.0.0.1 22'

# 3) Docker 네트워크 정책(다른 방화벽 체계가 있을 때)
iptables -S DOCKER-USER | head
nft list ruleset 2>/dev/null | head
```

**권장**: 포트 22 전체를 여는 대신, 이 계정의 SFTP 트래픽만 허용하는 좁은 예외를 둔다.

```bash
# 예시(리눅스 iptables): 컨테이너 브리지에서 이 계정으로만 22 접근 허용
iptables -I DOCKER-USER -p tcp --dport 22 -m owner --uid-owner <sshd-uid-of-user> -j ACCEPT
```

접근이 안 되면 플러그인이 `ECONNREFUSED` / `ETIMEDOUT` / `EHOSTUNREACH` 를
사람이 읽을 문장으로 바꾼다(`sftp_doctor` 가 그대로 보여준다).

---

## 3. sshd 설정 — 반드시 지켜야 할 두 가지

```sshd
# ★ 1) 포트 조건을 절대 넣지 않는다
#    Match User 에 LocalPort 가 있으면 같은 계정으로 다른 포트를 경유해
#    chroot/ForceCommand 를 우회할 수 있다. 적용은 인터페이스·포트와 무관해야 한다.
Match User <sftp-user>
    ChrootDirectory /srv/sftp-jail
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    PasswordAuthentication yes   # 비밀번호 인증을 쓴다면
```

**★ 2) `Match User` 는 파일의 마지막에 둔다** — 뒤에 다른 설정이 있으면
허용 규칙이 누적되어 일반 계정에까지 전파된다.

```bash
# 점검
sudo sshd -t                       # 문법 검사(반드시 reload 전에)
sudo sshd -T -C user=<sftp-user>,addr=127.0.0.1,host=localhost | \
  grep -Ei 'chrootdirectory|forcecommand|permitopen|allowtcpforwarding'
```

### 3.1 bind mount 와 쓰기 권한

```bash
mkdir -p /srv/sftp-jail/var/www /srv/sftp-jail/srv/remote-sandbox
mount --bind /var/www           /srv/sftp-jail/var/www
mount --bind /srv/remote-sandbox /srv/sftp-jail/srv/remote-sandbox
# 재부팅 후에도 유지되려면 /etc/fstab 에 --bind 항목 추가
```

jail 안에 있는 경로로 **이동하지 말 것**(bind mount 점을 덮어쓴다).

쓰기 권한은 **계정 그룹 소속**으로 얻는다. chroot 에 포함되었다고 자동으로 쓰기가 되지는 않는다.

```bash
id <sftp-user>                       # 소속 그룹 확인
sudo chgrp -R <write-group> /srv/remote-sandbox
sudo chmod -R 2775 /srv/remote-sandbox   # setgid
```

확인은 **`sftp_doctor({ probeWrite: true })`** 가 각 허용 루트에 임시 파일을 실제로 만들어
지우고 결과를 알려준다. 추측으로 하지 말고 이 도구를 믿을 것.

---

## 4. 비밀 파일 관리

```bash
install -d -m 700 ~/.config/opencode
cp sftp-guard/sftp-secrets.example.json ~/.config/opencode/sftp-secrets.json
chmod 600 ~/.config/opencode/sftp-secrets.json
```

| 규칙 | 이유 |
|---|---|
| 저장소 밖에 둔다 | 커밋·백업·로그에 섞이지 않는다 |
| 600 (또는 그보다 엄격) | 플러그인이 강제한다. group/other 가 읽으면 이미 유출된 것 |
| **환경변수로 비밀을 넘기지 않는다** | 프로세스 환경은 모델의 `bash` 도구로 노출된다. 플러그인이 의도적으로 거부한다 |
| 개인키도 600 | 동일 |
| 여러 명 계정이면 개별 파일 | 계정별 권한 분리 |

```bash
# 비밀 파일이 저장소에 들어가지 않도록(저장소 .gitignore 에도 있다)
git check-ignore -v sftp-guard/sftp-secrets.json
```

---

## 5. 감사 로그

- 기본: `~/.local/state/opencode/sftp-guard/audit.log` (XDG_STATE_HOME 준수)
- append-only, 5 MiB 회전 3본, 해시 체인

```bash
tail -f ~/.local/state/opencode/sftp-guard/audit.log
jq -c 'select(.outcome|test("denied|failed"))' ~/.local/state/opencode/sftp-guard/audit.log
# 누가 무엇을 승인받았는지
jq -c 'select(.approver=="human") | {ts, tool, resolved, risk}' ~/.local/state/opencode/sftp-guard/audit.log
# 변조 여부(체인이 맞는지)
node -e 'import("./sftp-guard/lib/core/index.mjs").then(m=>{
  const l=new m.AuditLog({path:process.env.HOME+"/.local/state/opencode/sftp-guard/audit.log"});
  console.log(l.verifyChain());
})'
```

로그는 **로컬 전용**이다. SFTP 로 절대 보내지 않으며, 원격 서버에 남는 흔적은 없다.

---

## 6. 갱신

```bash
cd /path/to/opencode-sftp-guard
git pull
./install.sh          # 파일 덮어쓰기 + 의존성 병합
# 비밀 파일은 건드리지 않는다(저장소 밖)
```

테스트를 먼저 돌리고 갱신하면 안전하다.

```bash
cd sftp-guard && node --test test/     # 132개
```

---

## 7. 트러블슈팅

| 증상 | 원인 | 조치 |
|---|---|---|
| 아무 질문 없이 바로 동작 | permission 규칙이 `allow` 로 평가됨 | `agents/sftp-remote.md` 의 permission 이 적용 중인지 확인. `sftp_doctor({probeGate:true})` |
| "승인 게이트가 살아 있지 않아 …" | 기본 `"*":"allow"` 에 걸림 | 오류 메시지에 필요한 설정 줄이 있다. frontmatter 에 `permission: { sftp_*: ask }` |
| `ECONNREFUSED` | sshd 미기동 / 다른 인터페이스 | §2 확인 |
| `ETIMEDOUT` / `EHOSTUNREACH` | Docker 네트워크 정책 | §2 확인 |
| `EACCES: 권한 거부` | 계정이 경로 소유 그룹에 속하지 않음 | §3.1 / `sftp_doctor({probeWrite:true})` |
| "경로 거부: 심볼릭 링크 … 허용 루트 밖" | 대상이 jail 밖을 가리킴 | 의도된 링크면 그 경로를 쓰지 말고 다른 경로 지정 |
| "수정 시 다른 세션이 이미 변경함" | 낙관적 동시성 검사 | `sftp_read` 로 다시 읽고 다시 판단 |
| "새 내용이 기존 내용과 동일" | 실질 변경 없음 | 쓰지 않음(의도된 동작) |
| "교체 실패: find 가 N곳에 등장" | 모호한 수정 | 더 긴 문맥을 넣거나 `all:true` |
| "부모 디렉터리를 확인할 수 없음" | 상위 폴더가 없음 | `sftp_mkdir` 로 먼저 생성 |
| "이상이 없음" binary | base64 로 일부만 전달됨 | 전체가 필요하면 `maxBytes` 를 올리고(base64 분할), 아니면 텍스트 파일만 다룸 |
| 감사 로그가 안 생김 | 경로 권한 | `auditPath` 확인. 로깅 실패는 작업을 막지 않는다 |
| 플러그인 로드 실패 | `plugins/` 아래 모듈이 별도 플러그인으로 로드됨 | 구현은 `sftp-guard/lib/` 아래 있어야 한다 |

---

## 8. 정기 점검 항목

```bash
# 1) 게이트가 살아 있는가 (사람이 있는 세션에서)
opencode --agent sftp-remote   # sftp_doctor({ probeGate: true })

# 2) 비밀 파일 권한
stat -c '%a %n' ~/.config/opencode/sftp-secrets.json     # 600 인지

# 3) sshd 설정이 의도대로인가
sudo sshd -T -C user=<sftp-user>,addr=127.0.0.1,host=localhost | \
  grep -Ei 'chrootdirectory|forcecommand'

# 4) 감사 로그 무결성
node -e 'import("./sftp-guard/lib/core/index.mjs").then(m=>{
  console.log(new m.AuditLog({path:process.env.HOME+"/.local/state/opencode/sftp-guard/audit.log"}).verifyChain());
})'

# 5) 의존성 버전이 고정과 일치하는가
cd ~/.config/opencode && npm ls ssh2-sftp-client
```

주기적으로 볼 것: 승인 로그의 `denied` 비율이 급증했다면 모델이 사람의 승인을 "지루해하고" 있다는
신호다. 그때는 범위를 좁히거나(`initialBasePath`) 자동 허용을 켜는 쪽을 검토할 것
([`README.md`](../README.md) §5.4).
