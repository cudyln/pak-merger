# 게임 프로필

[English](README.md) | 한국어

게임 프로필은 데이터베이스의 어떤 필드를 함께 선택해야 하는지 Pak Merger에 알려 줍니다. 새로운 파일 해석 기능을 추가하는 것은 아니므로, 데이터베이스 자체는 Pak Merger가 지원하는 형식이어야 합니다.

내장 프로필은 확실하게 일치하는 항목이 하나일 때 자동으로 적용됩니다. 일치하는 프로필이 없거나 여러 개가 같은 조건으로 맞으면 범용 비교 방식을 사용합니다.

내장 프로필은 두 개입니다. OCTOPATH TRAVELER 0(`octopath_traveler_0`)과 OCTOPATH TRAVELER II(`octopath_traveler_2`)입니다.

외부 JSON 프로필은 현재 Rust 라이브러리 API로 불러올 수 있습니다. GUI와 CLI에는 프로필 선택 기능이 아직 없습니다.

## 지원 형식

스키마 버전 1은 다음 두 형식을 지원합니다.

- `messagepack_m_data_list_v1`: 행이 `m_DataList`에 저장되고 `m_id`로 구분되는 MessagePack 데이터베이스.
- `ue4_datatable_v1`: 행을 이름으로 구분하는 쿡된 언리얼 엔진 4 `UDataTable`.

형식은 Pak Merger가 기대하는 쿡된 패키지 구조도 함께 결정하므로, 한 프로필 안에서 두 형식을 섞을 수 없습니다.

프로필은 다음 항목으로 구성됩니다.

- `schemaVersion`: 반드시 `1`이어야 합니다.
- `id`: 프로필 고유 식별자입니다.
- `displayName`: 사용자에게 표시할 이름입니다.
- `format`: `messagepack_m_data_list_v1` 또는 `ue4_datatable_v1`입니다.
- `detection`: 게임이나 데이터 구성을 판별할 Pak 내부 경로 조건입니다.
- `assets`: 데이터베이스 파일을 찾고 관련 필드를 묶는 규칙입니다.

`detection.rootScopeMatchers`를 지정하면 선택된 프로필이 다른 게임의
루트 경로에 적용되지 않습니다. 공통 Content 루트를 정리한 상대 경로에는
기존과 같은 방식으로 적용됩니다.

경로 조건은 `exact`, `prefix`, `suffix`, `contains` 중 하나를 사용합니다. 경로는 `/`로 시작하고 구분자로 `/`를 사용하며 대소문자를 구분하지 않습니다.

각 파일 규칙의 `fieldGroups`에는 다음 방식 중 하나를 사용할 수 있습니다.

- `whole_fields`: 나열한 필드를 모두 같은 Pak에서 선택합니다.
- `parallel_array_items`: 관련 배열의 길이가 같을 때 같은 순번끼리 묶어 선택합니다.

묶음에 적지 않은 값은 범용 규칙을 따릅니다. 최상위의 단순 값은 따로 선택할 수 있으며 배열과 중첩 값은 한 묶음으로 유지합니다.

## 표 사이 참조 검사

Pak Merger는 병합을 마친 뒤, 다른 표의 항목을 가리키는 값이 그 항목을 여전히 찾을 수 있는지 확인할 수 있습니다. 구조는 온전하지만 게임에서는 깨지는 Pak을 이 검사로 잡아냅니다.

이 규칙은 내장 프로필에만 있으며 스키마 1판에는 해당 항목이 없습니다. 어떤 필드의 값이 게임 원본 데이터에서 **전부** 다른 한 표의 항목일 때만 규칙으로 넣습니다. 대체로 맞는 정도의 규칙은 손대지 않은 데이터까지 깨졌다고 알리므로 넣지 않습니다.

규칙은 두 표가 모두 병합된 Pak에 있을 때만 동작합니다. 한쪽만 들어 있는 Pak은 다른 쪽에 대해 알려주는 바가 없으므로, 그런 규칙은 문제로 알리지 않고 건너뛴 사실만 알립니다.

## Rust 라이브러리 API

외부 프로필을 레지스트리에 등록한 뒤, 비교와 저장 모두 레지스트리가
지정된 분석 세션을 사용합니다. 저장이 끝날 때까지 같은 세션을 유지해야
합니다. 분석 계획만 받는 `write` 함수는 내장 프로필만 사용합니다.

```rust
use pak_merger::profiles::{ProfileRegistry, load_external_profile_file};
use pak_merger::{
    AnalysisRequest, ResolutionSet, WriteOptions, analyze_session_with_registry,
    write_session_with_options_and_progress,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

fn merge_with_profile(
    profile_path: &Path,
    first_pak: &Path,
    second_pak: &Path,
    output_pak: &Path,
    choices: BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ProfileRegistry::with_builtins();
    registry.register(load_external_profile_file(profile_path)?)?;
    let session = analyze_session_with_registry(
        AnalysisRequest {
            pak_paths: vec![first_pak.to_owned(), second_pak.to_owned()],
            carrier_path: first_pak.to_owned(),
        },
        Arc::new(registry),
    )?;

    // 각 항목은 session.plan()의 차단형 충돌 ID와 그 충돌에서 선택한
    // 값의 variant ID를 연결합니다.
    let resolutions = ResolutionSet {
        plan_id: session.plan().plan_id.clone(),
        choices,
    };
    write_session_with_options_and_progress(
        &session,
        resolutions,
        output_pak,
        WriteOptions::default(),
        |_| {},
    )?;
    Ok(())
}
```

## 예제

전체 형식은 가상 데이터로 만든 [`example-game.profile.json`](example-game.profile.json)에서 확인할 수 있습니다.
