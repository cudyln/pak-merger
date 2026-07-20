# 게임 프로필

[English](README.md) | 한국어

게임 프로필은 데이터베이스의 어떤 필드를 함께 선택해야 하는지 Pak Merger에 알려 줍니다. 새로운 파일 해석 기능을 추가하는 것은 아니므로, 데이터베이스 자체는 Pak Merger가 지원하는 형식이어야 합니다.

내장 프로필은 확실하게 일치하는 항목이 하나일 때 자동으로 적용됩니다. 일치하는 프로필이 없거나 여러 개가 같은 조건으로 맞으면 범용 비교 방식을 사용합니다.

외부 JSON 프로필은 현재 Rust 라이브러리 API로 불러올 수 있습니다. GUI와 CLI에는 프로필 선택 기능이 아직 없습니다.

## 지원 형식

스키마 버전 1은 `messagepack_m_data_list_v1`을 지원합니다. 행이 `m_DataList`에 저장되고 `m_id`로 구분되는 MessagePack 데이터베이스 형식입니다.

프로필은 다음 항목으로 구성됩니다.

- `schemaVersion`: 반드시 `1`이어야 합니다.
- `id`: 프로필 고유 식별자입니다.
- `displayName`: 사용자에게 표시할 이름입니다.
- `format`: 현재는 `messagepack_m_data_list_v1`입니다.
- `detection`: 게임이나 데이터 구성을 판별할 Pak 내부 경로 조건입니다.
- `assets`: 데이터베이스 파일을 찾고 관련 필드를 묶는 규칙입니다.

경로 조건은 `exact`, `prefix`, `suffix`, `contains` 중 하나를 사용합니다. 경로는 `/`로 시작하고 구분자로 `/`를 사용하며 대소문자를 구분하지 않습니다.

각 파일 규칙의 `fieldGroups`에는 다음 방식 중 하나를 사용할 수 있습니다.

- `whole_fields`: 나열한 필드를 모두 같은 Pak에서 선택합니다.
- `parallel_array_items`: 관련 배열의 길이가 같을 때 같은 순번끼리 묶어 선택합니다.

묶음에 적지 않은 값은 범용 규칙을 따릅니다. 최상위의 단순 값은 따로 선택할 수 있으며 배열과 중첩 값은 한 묶음으로 유지합니다.

## 예제

전체 형식은 가상 데이터로 만든 [`example-game.profile.json`](example-game.profile.json)에서 확인할 수 있습니다.
