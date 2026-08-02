package com.edrdog.responderservice.command;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 엔드포인트로 내려보낼 명령의 인메모리 큐.
 *
 * <p>에이전트가 방화벽 안쪽이라 서버가 먼저 부를 수 없어, 요청 스레드가 {@link #awaitResult} 에서
 * 에이전트의 다음 하트비트를 대신 기다린다. 영속 저장소는 두지 않는다.
 */
@Component
public class CommandQueue {

    private static final Logger log = LoggerFactory.getLogger(CommandQueue.class);

    /** 호스트별 미수령 명령. 에이전트가 하트비트로 가져간다. */
    private final Map<String, Queue<Command>> pending = new ConcurrentHashMap<>();
    /** 명령 id → 결과 대기 슬롯. complete 가 채우고 awaitResult 가 꺼낸다. */
    private final Map<String, CompletableFuture<String>> results = new ConcurrentHashMap<>();

    private final long ttlMs;
    private final Clock clock;

    @Autowired
    public CommandQueue(@Value("${edrdog.responder.command.ttl-ms}") long ttlMs) {
        this(ttlMs, Clock.systemUTC());
    }

    /** 만료 동작을 결정적으로 검증하려고 시계를 주입받는 생성자. */
    public CommandQueue(long ttlMs, Clock clock) {
        this.ttlMs = ttlMs;
        this.clock = clock;
    }

    /** 명령을 큐에 넣고 식별자를 돌려준다. 결과는 {@link #awaitResult} 로 기다린다. */
    public String dispatch(String host, String type, String target) {
        Instant now = clock.instant();
        expire(now);
        Command command = new Command(UUID.randomUUID().toString(), host, type, target, now);
        results.put(command.id(), new CompletableFuture<>());
        pending.computeIfAbsent(host, h -> new ConcurrentLinkedQueue<>()).add(command);
        log.info("[COMMAND-DISPATCH] id={} host={} type={} target={}", command.id(), host, type, target);
        return command.id();
    }

    /**
     * 결과가 올 때까지 블로킹한다. 시한을 넘기면 비어 있는 값. 슬롯은 기다리는 쪽이 치운다.
     * 에이전트가 방화벽 안쪽이라 이 대기가 필요하다. 시한을 빼면 하트비트가 끊긴 호스트에 요청 스레드가 묶인다.
     */
    public Optional<String> awaitResult(String id, Duration timeout) {
        CompletableFuture<String> slot = results.get(id);
        if (slot == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(slot.get(timeout.toMillis(), TimeUnit.MILLISECONDS));
        } catch (TimeoutException | ExecutionException e) {
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } finally {
            results.remove(id);
        }
    }

    /** 그 호스트의 대기 명령을 모두 꺼낸다. 한 번 꺼낸 명령은 다시 주지 않는다. */
    public List<Command> drainFor(String host) {
        Instant now = clock.instant();
        expire(now);
        Queue<Command> queue = pending.get(host);
        if (queue == null) {
            return List.of();
        }
        List<Command> drained = new ArrayList<>();
        for (Command c = queue.poll(); c != null; c = queue.poll()) {
            drained.add(c);
        }
        return drained;
    }

    /** 에이전트가 보고한 결과를 대기 중인 요청에 전달한다. */
    public void complete(String id, String status, String message) {
        // 슬롯은 여기서 지우지 않는다. 아직 대기에 못 들어간 요청이 결과를 놓친다.
        CompletableFuture<String> slot = results.get(id);
        if (slot == null) {
            // 이미 시한을 넘겼거나 만료된 명령. 늦게 온 보고는 버린다.
            log.info("[COMMAND-RESULT-LATE] id={} status={} (기다리는 요청 없음)", id, status);
            return;
        }
        log.info("[COMMAND-RESULT] id={} status={} message={}", id, status, message);
        slot.complete(status);
    }

    /** 아무도 가져가지 않은 명령을 TTL 기준으로 버린다. 오래 꺼진 호스트 때문에 큐가 무한히 자라지 않게 한다. */
    private void expire(Instant now) {
        Instant cutoff = now.minusMillis(ttlMs);
        pending.values().forEach(queue -> queue.removeIf(c -> {
            boolean stale = c.createdAt().isBefore(cutoff);
            if (stale) {
                results.remove(c.id());
                log.info("[COMMAND-EXPIRED] id={} host={} target={}", c.id(), c.host(), c.target());
            }
            return stale;
        }));
    }
}
