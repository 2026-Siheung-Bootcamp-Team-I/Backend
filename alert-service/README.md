# alert 모듈

`alerts` Kafka 토픽을 소비해 **tenant 별 Slack 채널**로 알림을 보낸다. (컨슈머 그룹 `alert`, responder 와 독립)

흐름: `alerts` 토픽 → `AlertListener` → 쿨다운 통과 시 `SlackNotifier` → tenant webhook 조회 → Slack Incoming Webhook

- alert 의 `tenantId` 로 api-service 내부 엔드포인트를 호출해 그 tenant 의 webhook 을 조회한다 (API 컴포지션).
- 같은 `tenant+host+ruleId` 는 쿨다운 창(기본 60초) 안에서 중복 발송을 억제한다 (Slack 스팸 방지).
- webhook 미등록(조회 결과 없음) 또는 `tenantId` 없는 alert 는 발송을 skip 하고 경고 로그만 남긴다.
- 전역 단일 webhook 폴백은 두지 않는다 (tenant 격리).

## tenant 별 Slack Webhook 등록 (알림 받는 방법)

알림을 받을 tenant 가 자기 Slack 에서 Webhook URL 을 발급받아 우리 앱에 등록하면 된다.

1. https://api.slack.com/apps → **Create New App** → **From scratch**
   (이미 앱이 있으면 그 앱을 열어도 된다)
2. 앱 이름과 알림 받을 워크스페이스를 선택
3. 왼쪽 메뉴 **Incoming Webhooks** → 토글을 **On** 으로
4. 하단 **Add New Webhook to Workspace** → 알림 받을 **채널 선택** → 승인
5. 생성된 `https://hooks.slack.com/services/XXX/YYY/ZZZ` URL 복사
6. 복사한 URL 을 로그인 세션으로 우리 앱에 등록:

   ```
   PUT /api/tenant/webhook
   { "webhookUrl": "https://hooks.slack.com/services/XXX/YYY/ZZZ" }
   ```

이후 그 tenant 의 alert 는 alert-service 가 `tenantId` 로 webhook 을 조회해 등록한 채널로 발송한다.

> 채널마다 URL 이 다르다. 다른 채널로 받으려면 그 채널로 Webhook 을 새로 추가해 다시 등록하면 된다.

## 조회 계약 (api-service 제공)

`GET {edrdog.api.base-url}/api/internal/tenants/{tenantId}/webhook`, 헤더 `X-API-Key: {edrdog.api.key}`
→ 200 `{"tenantId":<long>,"webhookUrl":<string|null>}`. 없는 tenant 는 404, `webhookUrl` 이 null 이면 미등록.
404 / null / 조회 에러는 모두 미등록으로 보고 발송을 skip 한다. 조회 결과는 짧은 TTL(기본 60초) 로 캐시한다.

## 실행

```bash
./gradlew :alert-service:bootRun
```

api-service 주소와 API 키가 기본값과 다르면 환경변수로 주입한다:

```bash
export EDRDOG_API_BASE_URL=http://localhost:8084
export EDRDOG_API_KEY=<internal-api-key>
./gradlew :alert-service:bootRun
```

## 설정 (application.yml)

| 키 | 기본값 | 설명 |
|----|--------|------|
| `edrdog.api.base-url` | `${EDRDOG_API_BASE_URL:http://localhost:8084}` | api-service 내부 엔드포인트 base URL |
| `edrdog.api.key` | `${EDRDOG_API_KEY:dev-api-key}` | 내부 엔드포인트 인증 `X-API-Key` |
| `edrdog.api.webhook-cache-ttl-ms` | `60000` | tenant webhook 조회 캐시 TTL |
| `edrdog.alert.cooldown-ms` | `60000` | 같은 tenant+host+ruleId 중복 발송 억제 창 |
| `edrdog.kafka.alerts-topic` | `alerts` | 소비할 토픽 |
| `server.port` | `8083` | 모듈 포트 |

## 메시지 예시

```
🔴 [CRITICAL] host=web-01 rule=SUSPICIOUS_PROCESS_CHAIN mitre=T1059 action=isolate
```
심각도 아이콘: CRITICAL 🔴 / HIGH 🟠 / 그 외 ⚪
