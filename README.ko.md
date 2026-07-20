# Pak Merger

[English](README.md) | 한국어

Pak Merger는 여러 모드 Pak을 하나의 파일로 합치는 도구입니다. 서로 겹치지 않는 변경 사항은 자동으로 합치고, 같은 항목을 서로 다르게 수정한 경우에는 어느 Pak의 내용을 사용할지 직접 선택할 수 있습니다.

Windows GUI와 CLI가 하나의 `pak-merger.exe`에 들어 있습니다. UnrealPak은 필요하지 않습니다.

## 병합할 수 있는 내용

- 한 Pak에만 있는 파일은 자동으로 추가합니다.
- 입력 Pak이 게임의 `Content` 폴더 안에서 서로 다른 경로를 수정해도 함께 합칠 수 있습니다.
- 지원되는 데이터베이스는 파일 전체를 한쪽으로 덮지 않고 필드별 변경을 합칩니다.
- 두 Pak이 같은 필드를 서로 다르게 바꾼 경우 어느 쪽 값을 남길지 직접 선택합니다.
- 안전하게 비교할 수 없는 파일은 관련 파일 묶음 전체를 어느 Pak에서 가져올지 선택합니다.

데이터베이스 필드 병합은 현재 OCTOPATH TRAVELER 0에 맞춰져 있습니다. 다른 Unreal Pak도 읽을 수 있으면 합칠 수 있지만, 구조를 알 수 없는 데이터는 파일 전체를 선택해야 할 수 있습니다.

## 지원 파일

- Windows x64
- 한 작업에 최대 64개 Pak, 합계 128 GiB
- 비암호화 Pak v0~v11 입력
- 무압축, Zlib, Gzip, Zstd, LZ4, Oodle 입력
- 비암호화·비서명 Pak v11 출력
- 무압축 또는 Oodle 출력
- 한국어, 영어, 일본어 화면과 이용약관

암호화 Pak, IoStore(`.utoc`/`.ucas`), 손상된 파일, 지원하지 않는 압축 형식은 열 수 없습니다. AES 키 입력 기능은 없습니다.

Oodle 기능에는 `oo2core_9_win64.dll`이 필요합니다. 파일이 없으면 Oodle을 처음 사용할 때 내려받아 확인합니다. 이 과정에는 인터넷 연결과 실행 파일이 있는 폴더의 쓰기 권한이 필요합니다.

## GUI 사용 방법

1. `pak-merger.exe`를 실행하고 이용약관에 동의합니다.
2. 합칠 Pak을 두 개 이상 추가합니다. 파일을 창으로 끌어다 놓아도 됩니다.
3. **기준 Pak**을 고릅니다. 별도 선택이 필요 없는 내용은 기준 Pak 쪽 형식을 유지하지만, 충돌에서 자동으로 우선되지는 않습니다.
4. **분석**을 누릅니다.
5. 해결되지 않은 각 항목에 사용할 Pak을 선택합니다.
6. **병합 Pak 생성**을 누릅니다.

기본 파일 이름은 `ZZMerge_P.pak`입니다. `ZZ` 접두사는 일반적인 파일 이름 기준 로드 순서에서 병합 Pak이 뒤쪽에 놓이도록 돕습니다. 이름은 바꿀 수 있지만 `_P.pak`으로 끝내세요.

같은 이름의 파일이 이미 있으면 교체하기 전에 확인합니다. 입력 Pak은 읽기 전용으로 열며 자동으로 이동, 삭제, 설치하지 않습니다.

병합 후에는 새로 만든 Pak만 게임에 넣으세요. 원래 모드 Pak을 함께 불러오면 병합 결과의 일부가 다시 덮어써질 수 있습니다.

## 임시 파일과 여유 공간

작업 중인 파일은 `pak-merger.exe` 옆의 `tmp` 폴더에 저장됩니다. 병합 Pak은 다른 드라이브에도 저장할 수 있지만, 작업 드라이브와 저장 드라이브 양쪽에 충분한 여유 공간이 필요합니다.

## 옵션과 진행 상황

기본값은 **Oodle 압축**과 **멀티스레드 사용**입니다.

- 압축 계산 없이 더 큰 파일을 만들려면 **무압축**을 선택하세요.
- 문제를 확인할 때만 **멀티스레드**를 끄세요.
- 분석이나 Pak 생성 중에는 출력 옵션을 바꿀 수 없습니다.

화면에서 현재 단계와 진행률을 확인할 수 있습니다. **작업 취소**를 누르면 가능한 시점에 중단하고 Pak Merger가 만든 임시 파일을 정리합니다.

## CLI

전체 명령과 옵션은 내장 도움말에서 확인할 수 있습니다.

```powershell
.\pak-merger.exe --help
.\pak-merger.exe <command> --help
```

기본 작업 예시:

```powershell
.\pak-merger.exe inspect '.\ModA_P.pak'

.\pak-merger.exe analyze `
  --pak '.\ModA_P.pak' `
  --pak '.\ModB_P.pak' `
  --base-pak '.\ModA_P.pak' `
  --output '.\merge-plan.json'

.\pak-merger.exe merge `
  --plan '.\merge-plan.json' `
  --choose 'conflict-id=pak-option-id' `
  --output '.\ZZMerge_P.pak'

.\pak-merger.exe verify '.\ZZMerge_P.pak'
```

`merge`는 `--overwrite`를 지정하지 않으면 기존 출력 파일을 교체하지 않습니다. 무압축으로 저장하려면 `--compression none`을 추가하세요. 기본값은 Oodle입니다.

### 이용약관

```powershell
.\pak-merger.exe eula
.\pak-merger.exe eula --true
```

`eula`는 포함된 약관을 보여 줍니다. 내용을 읽은 뒤 `eula --true`를 실행하면 동의가 저장됩니다. 확인한 언어를 기록하려면 `--locale ko`, `--locale en`, `--locale ja` 중 하나를 덧붙일 수 있으며 기본값은 영어입니다.

동의 상태 확인과 철회 명령은 `.\pak-merger.exe eula --help`에서 확인할 수 있습니다.

## 라이선스

Pak Merger 자체 코드는 [Pak Merger Non-Commercial Source License](LICENSE)에 따라 개인적·비상업적 목적으로 사용할 수 있습니다. 제3자 구성요소에는 각 라이선스가 적용됩니다. 자세한 내용은 [제3자 고지문](THIRD_PARTY_NOTICES.md)을 확인하세요.
