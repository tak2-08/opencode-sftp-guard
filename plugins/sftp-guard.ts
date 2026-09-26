// sftp-guard 플러그인 진입점.
//
// 로딩 위치(실측, opencode 1.18.22):
//   - 전역: ~/.config/opencode/plugins/*.{ts,js}
//   - 프로젝트: .opencode/plugins/*.{ts,js}   ← 이 파일
//   (중요: 이 글롭은 *한 단계*만 훑는다. plugins/ 아래에 넣은 .ts 는 각각 별도 플러그인으로
//    로드되므로, 보조 모듈을 plugins/ 안에 두면 플러그인으로 오인된다. 그래서 구현은
//    ../sftp-guard/lib/ 아래에 두고 여기서만 진입한다.)
//
// 논리 구현: ../sftp-guard/lib/oc/plugin.ts
// 런타임 독립 코어: ../sftp-guard/lib/core/*.mjs (Node 테스트 하네스와 Bun 양쪽에서 동일 실행)
import { createSftpGuard } from "../sftp-guard/lib/oc/plugin";

/**
 * @type {import("@opencode-ai/plugin").Plugin}
 */
export const SftpGuardPlugin = async (input) => createSftpGuard(input);
