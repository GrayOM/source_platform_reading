# Scan Policy and Safety Guardrails

Scan policy는 크롤러가 어디까지, 어떤 속도로, 어떤 범위 안에서 수집할지 제한하는 안전 장치입니다. 정책 값과 정책 위반/차단 이벤트는 scan config에 저장되고 report와 evidence bundle에 포함됩니다.

## Profiles

- `careful`: UI 기본값입니다. 낮은 concurrency, request delay, 작은 page/resource/depth 제한으로 데모와 안전한 확인에 적합합니다.
- `normal`: 허가받은 일반 진단에서 careful보다 넓은 범위를 수집할 때 사용합니다.
- `low`: 더 낮은 강도나 제한적 확인이 필요한 경우 사용합니다.

Profile 이름은 기본 방향을 나타냅니다. 실제 제한은 아래 개별 필드가 우선합니다.

## Limits

- `max_pages`: 수집할 최대 page 수입니다. 도달하면 `max_pages_reached` policy event가 기록될 수 있습니다.
- `max_resources`: 수집할 최대 resource 수입니다. 도달하면 `max_resources_reached` policy event가 기록될 수 있습니다.
- `max_depth`: 시작 URL로부터 따라갈 최대 link depth입니다.
- `max_concurrency`: 동시에 처리할 요청/페이지 작업 수입니다. 로컬 데모 기본값은 보수적으로 `1`을 사용합니다.
- `request_delay_ms`: 요청 사이에 둘 delay입니다.
- `request_timeout_ms`: 개별 요청 timeout입니다. timeout은 graceful하게 처리되고 `request_timeout` event로 남을 수 있습니다.

## Scope Controls

- `same_origin_only`: target origin 밖의 링크와 redirect를 기본 차단합니다.
- `allowed_hosts`: target host 외에 허용할 host 목록입니다. target host는 자동으로 포함됩니다.
- `excluded_hosts`: 발견하더라도 수집하지 않을 host 목록입니다.
- `excluded_paths`: logout, destructive action, 큰 media 경로처럼 제외할 path 목록입니다.
- `respect_robots_txt`: robots 정책 반영을 위한 선택 필드입니다.

Excluded path는 일반 crawl config와 scan policy에 모두 반영됩니다. 제외된 URL은 `excluded_path_skipped` policy event로 남을 수 있습니다.

## Private Target Policy

기본 정책은 private, loopback, link-local, reserved 주소를 차단합니다. 개발/E2E 환경에서는 `SSRF_ALLOWED_HOSTS`에 명시된 host만 예외적으로 허용할 수 있습니다.

관련 설정:

- `.env` 또는 Compose 환경의 `SSRF_ALLOWED_HOSTS`
- `ALLOW_PRIVATE_TARGETS`
- scan policy의 `allow_private_targets`

Private target이 차단되면 `private_target_blocked` policy event가 기록됩니다.

## Redirect Outside Scope Policy

`same_origin_only=true`이고 `allow_redirect_outside_scope`가 켜져 있지 않으면 outside-scope redirect는 차단됩니다. 이 경우 `outside_scope_blocked` policy event가 기록됩니다.

로컬 fixture `/redirect-outside`는 이 동작을 확인하기 위한 route입니다.

## Capture Controls

- `capture_screenshots`: page screenshot artifact를 남길지 결정합니다.
- `capture_storage`: storage evidence를 수집할지 결정합니다.
- `capture_api_flows`: browser-observed API flow를 수집할지 결정합니다.
- `authorization_confirmed`: 사용자가 해당 대상과 범위에 대한 스캔 권한을 확인했는지 기록합니다. 확인되지 않으면 `authorization_not_confirmed` event가 저장될 수 있습니다.

## Policy Events

`policy_events`는 안전 제한으로 인해 발생한 주요 결정을 기록합니다.

대표 event:

- `authorization_not_confirmed`
- `excluded_path_skipped`
- `outside_scope_blocked`
- `private_target_blocked`
- `max_pages_reached`
- `max_resources_reached`
- `request_timeout`

각 event는 보통 다음 정보를 포함합니다.

- `event_type`
- `url`
- `message`
- `policy_field`
- `severity`

Policy event는 취약점 finding이 아닙니다. 수집 범위가 어떻게 제한되었는지 설명하는 감사 기록입니다.

## Report and Bundle Recording

Report에는 scan policy와 policy event summary가 포함됩니다. Evidence bundle에는 다음 파일이 포함됩니다.

- `reports/scan_policy.json`
- `reports/policy_events.json`
- root-level `scan_policy.json`
- root-level `policy_events.json`
- `manifest.json`의 `policy_event_count`

이 파일들은 보고서 수신자가 scan이 허가된 범위 안에서 수행되었는지, 어떤 URL이 scope 밖으로 차단되었는지, timeout이나 limit 도달이 있었는지 확인하는 데 사용됩니다.
