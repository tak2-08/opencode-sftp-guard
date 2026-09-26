// 설정/비밀 로더 — §0 "read once at plugin init from a local secrets source the model never touches".
//
// 설계:
//  - 비밀은 오직 두 곳에서만 나온다: (1) ~/.config/opencode/sftp-secrets.json, (2) 비밀키 파일 경로.
//  - 비밀번호/패스프레이즈를 환경변수로 받는 것은 기본적으로 금지한다.
//    이유: opencode 는 AI 쉘/사용자 쉘을 같은 프로세스 계층에서 띄우므로, 프로세스 환경에 있는 값은
//    모델이 가진 bash 로 `env` 출력만으로 새어 나간다. §0 의 "shell.env 훅 금지" 와 같은 이유.
//    호스트/포트/사용자명처럼 비밀값이 아닌 것만 환경변수 허용.
//  - 파일 권한을 실제로 검사한다(600 이 아니면 거부 — world-readable 비밀은 비밀 아니다).
//  - 여기서 읽은 값은 즉시 registerSecret() 으로 등록되고, 그 뒤 모든 아웃바운드는 redact 대상이 된다.
import { readFileSync, statSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, isAbsolute, resolve as resolvePath } from "node:path";
import { asBool, asNumber, clamp } from "./util.mjs";
import { registerSecret, listSecretLabels } from "./redact.mjs";
import { defaultAuditPath } from "./audit.mjs";

export const DEFAULT_SECRETS_PATH = () => join(homedir(), ".config", "opencode", "sftp-secrets.json");
export const DEFAULT_CONFIG_PATH = () => join(homedir(), ".config", "opencode", "sftp-guard.json");

/** §0.1 기본값: 전용 SFTP 계정 + 컨테이너→호스트 루프백. */
export const DEFAULT_CONNECTION = {
  host: "127.0.0.1",
  port: 22,
  // ★ 기본값을 두지 않는다. 계정명을 소스에 박아두면 배포 저장소에 사용자 이름이 새고,
  //   누락된 설정을 조용한 실패로 두게 된다. 비밀 파일에서 반드시 명시할 것.
  username: "",
  readyTimeoutMs: 20_000,
  keepaliveIntervalMs: 15_000,
  keepaliveCountMax: 3,
};

/** §0.1 의 두 bind mount (chroot 안에서 보이는 경로). */
export const DEFAULT_ALLOWED_ROOTS = ["/var/www/html", "/srv/remote-sandbox"];

/**
 * 정책 기본값. 모든 값이 fail-closed 방향이다.
 * @see README.md §2 승인 매트릭스
 */
export const DEFAULT_POLICY = {
  // 읽기/목록
  maxReadBytes: 2 * 1024 * 1024, // 모델 트랜스크립트로 넘길 수 있는 최대 크기
  maxWalkEntries: 2000, // propose_scope 가 볼 항목 수 상한
  maxWalkDepth: 3,
  // 쓰기
  maxWriteBytes: 8 * 1024 * 1024,
  defaultFileMode: 0o644,
  // 승인
  approvalTimeoutMs: 10 * 60 * 1000, // §5 기본 10분, 초과 시 DENY
  requireLiveGate: true, // permission.asked 이벤트 관측 실패(allow 룰에 의한 우회) 시 DENY
  approveAllBatchCap: 20, // §5 approve-all 배치 상한
  allowModelApproveAll: false, // 모델이 sftp_set_mode 로 approve-all 을 켤 수 없음(하드닝)
  // 감사자
  auditor: {
    enabled: false, // 기본 꺼짐(§4)
    agent: "risk-auditor",
    maxRetries: 2, // 같은 대상 경로당 재시도 상한
    timeoutMs: 120_000,
    deleteChildSession: true,
  },
  // 로그
  audit: { enabled: true, maxBytes: 5 * 1024 * 1024, keepRotations: 3, hashChain: true },
  // 사전 검사
  initialBasePath: null, // 사람이 정해 둔 기준 경로(있으면 propose_scope 가 이 안으로만 허용)
  // 웹셸 하드 시그니처 검사 상한
  maxScanBytes: 4 * 1024 * 1024,
  // 바이너리/인코딩
  redactSecretLookingContentOnRead: true,
  // 연결 실패 시 재시도
  connectRetries: 1,
};

class ConfigError extends Error {}

/**
 * 비밀 파일 로드 + 검증 + 비밀값 등록.
 * @param {string} secretsPath
 * @returns {{connection: object, privateKeyPath?: string, source: string}}
 */
export function loadSecrets(secretsPath = DEFAULT_SECRETS_PATH()) {
  if (!existsSync(secretsPath)) {
    throw new ConfigError(
      `SFTP 비밀 파일을 찾을 수 없음: ${secretsPath}\n` +
        `템플릿을 .opencode/sftp-guard/sftp-secrets.example.json 에서 복사하고 chmod 600 으로 두세요.`,
    );
  }
  const stat = statSync(secretsPath);
  const mode = stat.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new ConfigError(
      `SFTP 비밀 파일 권한이 느슨함: ${secretsPath} (mode=${mode.toString(8)}). ` +
        `group/other 접근이 있는 비밀은 비밀 아니다 — chmod 600 ${secretsPath}`,
    );
  }
  let raw;
  try {
    raw = readFileSync(secretsPath, "utf8");
  } catch (err) {
    throw new ConfigError(`SFTP 비밀 파일을 읽을 수 없음: ${secretsPath} (${err?.code ?? "unknown"})`);
  }
  let json;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    // 파싱 오류 메시지에 원본 조각이 실릴 수 있으므로 등록/스크럽 대상이 아니게 짧게만 남긴다.
    throw new ConfigError(`SFTP 비밀 파일이 JSON 이 아님: ${secretsPath}`);
  }

  const host = envOr(json.connection?.host ?? json.host, process.env.SFTP_GUARD_HOST, DEFAULT_CONNECTION.host);
  const port = asNumber(envOr(json.connection?.port ?? json.port, process.env.SFTP_GUARD_PORT, DEFAULT_CONNECTION.port), DEFAULT_CONNECTION.port);
  const username = envOr(
    json.connection?.username ?? json.username,
    process.env.SFTP_GUARD_USERNAME,
    DEFAULT_CONNECTION.username,
  );
  const readyTimeoutMs = asNumber(
    envOr(json.connection?.readyTimeoutMs, process.env.SFTP_GUARD_READY_TIMEOUT_MS, DEFAULT_CONNECTION.readyTimeoutMs),
    DEFAULT_CONNECTION.readyTimeoutMs,
  );

  const password = typeof json.password === "string" ? json.password : undefined;
  const privateKeyPathRaw = json.privateKeyPath ?? json.keyPath;
  const passphrase = typeof json.passphrase === "string" ? json.passphrase : undefined;

  // 환경변수 비밀 거부 판정은 "자격증명이 하나도 없다" 검사보다 먼저 한다.
  // 운영자가 env 로 비밀을 넘기려 한 경우, 그 사유를 그대로 알려주는 것이 우선이다.
  if (json.passwordFromEnv === true || process.env.SFTP_GUARD_PASSWORD) {
    throw new ConfigError(
      "환경변수 기반 비밀은 거부됨. §0: 셸 환경은 모델의 bash 도구로 노출되므로 비밀을 프로세스 환경에 두지 않는다. 비밀 파일을 쓰세요.",
    );
  }
  if (!password && !privateKeyPathRaw) {
    throw new ConfigError(`비밀 파일에 password 도 privateKeyPath 도 없음: ${secretsPath}`);
  }

  // 비밀값 등록(순서: 패스워드 → 패스프레이즈). 이후 모든 출력은 스크럽된다.
  if (password) registerSecret(password, "sftp.password");
  if (passphrase) registerSecret(passphrase, "sftp.passphrase");
  if (privateKeyPathRaw) registerSecret(String(privateKeyPathRaw), "sftp.privateKeyPath");

  let privateKeyPath;
  if (privateKeyPathRaw) {
    privateKeyPath = isAbsolute(String(privateKeyPathRaw))
      ? String(privateKeyPathRaw)
      : resolvePath(join(homedir(), String(privateKeyPathRaw)));
    // 비밀키 파일도 600 을 요구한다(사설키는 644 면 이미 유출된 것).
    if (existsSync(privateKeyPath)) {
      const km = statSync(privateKeyPath).mode & 0o777;
      if ((km & 0o077) !== 0) {
        throw new ConfigError(`개인키 파일 권한이 느슨함: ${privateKeyPath} (mode=${km.toString(8)}) — chmod 600 하세요.`);
      }
    }
  }

  return {
    source: secretsPath,
    connection: {
      host,
      port: clamp(port, 1, 65_535),
      username,
      password,
      privateKeyPath,
      passphrase,
      readyTimeoutMs: clamp(readyTimeoutMs, 1_000, 120_000),
      keepaliveIntervalMs: asNumber(json.connection?.keepaliveIntervalMs, DEFAULT_CONNECTION.keepaliveIntervalMs),
      keepaliveCountMax: asNumber(json.connection?.keepaliveCountMax, DEFAULT_CONNECTION.keepaliveCountMax),
      algorithms: json.connection?.algorithms, // 선택적
    },
  };
}

function envOr(value, envValue, fallback) {
  if (value !== undefined && value !== null && value !== "") return value;
  if (envValue !== undefined && envValue !== null && envValue !== "") return envValue;
  return fallback;
}

/**
 * 정책 파일 로드(비밀 없음) + 기본값 병합 + 검증.
 * @param {string} configPath
 */
export function loadPolicy(configPath = DEFAULT_CONFIG_PATH()) {
  let file = {};
  if (existsSync(configPath)) {
    try {
      file = JSON.parse(readFileSync(configPath, "utf8"));
    } catch {
      throw new ConfigError(`정책 파일이 JSON 이 아님: ${configPath}`);
    }
  }
  const merged = {
    ...DEFAULT_POLICY,
    // 중첩 "limits": {...} 형태도 허용(예시 파일 가독성용). 평평한 키가 우선이므로 뒤에 둔다.
    ...pick(file.limits ?? {}, Object.keys(DEFAULT_POLICY)),
    ...pick(file, Object.keys(DEFAULT_POLICY)),
    auditor: { ...DEFAULT_POLICY.auditor, ...pick(file.auditor ?? {}, Object.keys(DEFAULT_POLICY.auditor)) },
    audit: { ...DEFAULT_POLICY.audit, ...pick(file.audit ?? {}, Object.keys(DEFAULT_POLICY.audit)) },
  };
  merged.allowedRoots = normalizeRoots(file.allowedRoots ?? DEFAULT_ALLOWED_ROOTS);
  if (merged.allowedRoots.length === 0) throw new ConfigError("allowedRoots 가 비어 있음 — fail-closed 를 위해 최소 1개 필요");
  // 감사 로그 경로(XDG 기본, 환경변수/설정 파일로 재정의 가능)
  merged.auditPath = file.auditPath || process.env.SFTP_GUARD_AUDIT_LOG || defaultAuditPath();
  // 웹셸 하드 시그니처 deny 를 outright DENY 로 만들지 여부(기본 false = 인간에게 escalate, §4)
  merged.denyHardContentWrites = asBool(file.denyHardContentWrites, false) === true;
  merged.approvalTimeoutMs = clamp(asNumber(merged.approvalTimeoutMs, DEFAULT_POLICY.approvalTimeoutMs), 5_000, 3 * 60 * 60 * 1000);
  merged.maxReadBytes = clamp(asNumber(merged.maxReadBytes, DEFAULT_POLICY.maxReadBytes), 1024, 64 * 1024 * 1024);
  merged.maxWriteBytes = clamp(asNumber(merged.maxWriteBytes, DEFAULT_POLICY.maxWriteBytes), 1024, 128 * 1024 * 1024);
  merged.approveAllBatchCap = clamp(asNumber(merged.approveAllBatchCap, DEFAULT_POLICY.approveAllBatchCap), 1, 10_000);
  merged.auditor.maxRetries = clamp(asNumber(merged.auditor.maxRetries, DEFAULT_POLICY.auditor.maxRetries), 0, 10);
  merged.auditor.timeoutMs = clamp(asNumber(merged.auditor.timeoutMs, DEFAULT_POLICY.auditor.timeoutMs), 5_000, 600_000);
  merged.auditor.enabled = asBool(merged.auditor.enabled, false) === true;
  merged.audit.enabled = asBool(merged.audit.enabled, true) !== false;
  merged.audit.hashChain = asBool(merged.audit.hashChain, true) !== false;
  merged.requireLiveGate = asBool(merged.requireLiveGate, true) !== false;
  merged.allowModelApproveAll = asBool(merged.allowModelApproveAll, false) === true;
  merged.redactSecretLookingContentOnRead = asBool(merged.redactSecretLookingContentOnRead, true) !== false;
  if (merged.initialBasePath) merged.initialBasePath = normalizeRoot(merged.initialBasePath);
  return merged;
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj && obj[k] !== undefined) out[k] = obj[k];
  return out;
}

function normalizeRoots(list) {
  return (Array.isArray(list) ? list : [list]).filter(Boolean).map(normalizeRoot);
}

function normalizeRoot(p) {
  const s = String(p).replace(/\\/g, "/").replace(/\/+$/, "");
  return s === "" ? "/" : s;
}

/** 진단용 요약(비밀값 없음). */
export function describeConfig(loadedSecrets, policy) {
  return {
    secretsSource: loadedSecrets.source,
    auth: loadedSecrets.connection.password ? "password" : "privateKey",
    registeredSecretLabels: listSecretLabels(),
    allowedRoots: policy.allowedRoots,
    approvalTimeoutMs: policy.approvalTimeoutMs,
    requireLiveGate: policy.requireLiveGate,
    allowModelApproveAll: policy.allowModelApproveAll,
    auditorEnabled: policy.auditor.enabled,
    initialBasePath: policy.initialBasePath,
    limits: {
      maxReadBytes: policy.maxReadBytes,
      maxWriteBytes: policy.maxWriteBytes,
      maxWalkDepth: policy.maxWalkDepth,
      maxWalkEntries: policy.maxWalkEntries,
      approveAllBatchCap: policy.approveAllBatchCap,
    },
  };
}

export { ConfigError };
