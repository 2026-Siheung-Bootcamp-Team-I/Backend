# alert 모듈

`alerts` Kafka 토픽을 소비해 Slack 으로 알림을 보낸다. (컨슈머 그룹 `alert`, responder 와 독립)

흐름: `alerts` 토픽 → `AlertListener` → 쿨다운 통과 시 `SlackNotifier` → Slack Incoming Webhook

- 같은 `host+ruleId` 는 쿨다운 창(기본 60초) 안에서 중복 발송을 억제한다 (Slack 스팸 방지).
- `SLACK_WEBHOOK_URL` 미설정 시 발송을 skip 하고 경고 로그만 남긴다 (webhook 없이도 소비 흐름 테스트 가능).

## Slack Incoming Webhook 발급 (알림 받는 방법)

알림을 받으려면 받을 사람이 자기 Slack 에서 Webhook URL 을 발급받아 우리 앱에 넣어주면 된다.

1. https://api.slack.com/apps → **Create New App** → **From scratch**
   (이미 앱이 있으면 그 앱을 열어도 된다)
2. 앱 이름과 알림 받을 워크스페이스를 선택
3. 왼쪽 메뉴 **Incoming Webhooks** → 토글을 **On** 으로
4. 하단 **Add New Webhook to Workspace** → 알림 받을 **채널 선택** → 승인
5. 생성된 `https://hooks.slack.com/services/XXX/YYY/ZZZ` URL 복사

복사한 URL 을 `SLACK_WEBHOOK_URL` 로 주입한다. (아래 실행 참고)

> 채널마다 URL 이 다르다. 다른 채널로 받으려면 그 채널로 Webhook 을 새로 추가하면 된다.

## 실행

```bash
# 1) 루트의 .env.example 를 .env 로 복사하고 SLACK_WEBHOOK_URL 채우기
cp .env.example .env
# .env 편집: SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# 2) 셸에 주입 후 실행 (Spring Boot 는 .env 를 자동으로 읽지 않는다)
export $(grep -v '^#' .env | xargs)
./gradlew :alert:bootRun
```

IDE 로 실행할 땐 실행 구성의 Environment variables 에 `SLACK_WEBHOOK_URL` 을 넣어도 된다.

## 설정 (application.yml)

| 키 | 기본값 | 설명 |
|----|--------|------|
| `edrdog.slack.webhook-url` | `${SLACK_WEBHOOK_URL:}` | Slack Incoming Webhook URL (비면 발송 skip) |
| `edrdog.alert.cooldown-ms` | `60000` | 같은 host+ruleId 중복 발송 억제 창 |
| `edrdog.kafka.alerts-topic` | `alerts` | 소비할 토픽 |
| `server.port` | `8083` | 모듈 포트 |

## 메시지 예시

```
🔴 [CRITICAL] host=web-01 rule=SUSPICIOUS_PROCESS_CHAIN mitre=T1059 action=isolate
```
심각도 아이콘: CRITICAL 🔴 / HIGH 🟠 / 그 외 ⚪
