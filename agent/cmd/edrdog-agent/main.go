// edrdog-agent 는 엔드포인트에서 행위를 관찰해 서버로 보내고, 서버가 내린 조치를 실행하는 수집기다.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	goruntime "runtime"
	"sync"
	"syscall"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/command"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/config"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/runtime"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/sensor"
	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/transport"
)

// version 은 서버에 알리는 에이전트 판번호다. 릴리즈할 때 -ldflags 로 덮어쓴다.
var version = "0.1.0"

type options struct {
	configPath       string
	logPath          string
	selfTest         bool
	selfTestInterval time.Duration
	asService        bool
}

func main() {
	var opts options
	flag.StringVar(&opts.configPath, "config", "", "설정 파일 경로")
	flag.StringVar(&opts.logPath, "log", "", "로그 파일 경로. 비우면 stderr (Windows 서비스는 stderr 가 아무 데도 가지 않는다)")
	flag.BoolVar(&opts.selfTest, "selftest", false, "진짜 센서 대신 가짜 이벤트를 보내 서버까지의 경로를 확인한다")
	flag.DurationVar(&opts.selfTestInterval, "selftest-interval", time.Second, "자체 점검 이벤트 주기")
	flag.BoolVar(&opts.asService, "service", false, "Windows 서비스로 실행한다(설치 스크립트가 붙인다)")
	flag.Parse()

	out, closeLog, err := openLogWriter(opts.logPath)
	if err != nil {
		// 여기서만 stderr 로 적는다: 로그 파일을 못 열었다는 사실은 어디엔가는 남아야 한다.
		fmt.Fprintf(os.Stderr, "로그 파일을 열지 못했다: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = closeLog() }()

	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if opts.asService {
		if err := runAsService(opts, log); err != nil {
			log.Error("서비스 실행 실패", "err", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runAgent(ctx, opts, log); err != nil {
		log.Error("에이전트가 멈췄다", "err", err)
		os.Exit(1)
	}
}

// runAgent 는 ctx 가 끝나면 정리하고 돌아온다.
func runAgent(ctx context.Context, opts options, log *slog.Logger) error {
	if opts.configPath == "" {
		return fmt.Errorf("-config 가 필요하다")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	httpClient, err := cfg.HTTPClient()
	if err != nil {
		return err
	}

	client := transport.NewClient(transport.Config{
		BaseURL:      cfg.BaseURL,
		EnrollSecret: cfg.EnrollSecret,
		HostID:       cfg.HostIdentifier,
		// 서버는 이 값에 windows 가 들어있는지로 수집 설정을 가른다.
		Platform:     goruntime.GOOS,
		AgentVersion: version,
		Timeout:      cfg.FlushInterval(),
	}, httpClient)

	if err := client.Enroll(ctx); err != nil {
		return fmt.Errorf("등록 실패: %w", err)
	}
	log.Info("등록 완료", "host", cfg.HostIdentifier, "platform", goruntime.GOOS, "version", version)

	// 첫 하트비트로 어떤 센서를 켤지·어디를 감시할지 수집 설정을 받는다.
	beat, err := client.Heartbeat(ctx)
	if err != nil {
		return fmt.Errorf("수집 설정을 받지 못했다: %w", err)
	}

	factory := event.Factory{Host: cfg.HostIdentifier}
	sensors, err := buildSensors(factory, beat.Config, opts, log)
	if err != nil {
		return err
	}
	names := make([]string, len(sensors))
	for i, s := range sensors {
		names[i] = s.Name()
	}

	// 전송 주기는 서버가 정한다(엔드포인트에 손대지 않고 조절 가능해야 함).
	flush := cfg.FlushInterval()
	if beat.Config.FlushIntervalSeconds > 0 {
		flush = time.Duration(beat.Config.FlushIntervalSeconds) * time.Second
	}

	engine := runtime.New(client, runtime.Options{
		BufferSize:    cfg.BufferSize,
		BatchSize:     cfg.BatchSize,
		FlushInterval: flush,
		Logger:        log,
	})
	commands := command.New(client, command.NewKiller(), command.Options{Logger: log})

	// 하트비트 응답에 실려 온 대기 명령. 서버는 한 번 내준 명령을 다시 주지 않으므로 여기서 처리해야 한다.
	commands.Execute(ctx, beat.Commands)

	log.Info("수집 시작", "sensors", names, "flush", flush, "watch", beat.Config.WatchPaths)

	// 수집과 조치는 서로를 기다리면 안 된다.
	var wg sync.WaitGroup
	var collectErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		collectErr = engine.Run(ctx, sensors)
	}()
	go func() {
		defer wg.Done()
		if err := commands.Run(ctx); err != nil {
			log.Error("조치 채널이 멈췄다", "err", err)
		}
	}()
	wg.Wait()

	log.Info("종료", "dropped", engine.Buffer().Dropped())
	return collectErr
}

// buildSensors 는 돌릴 센서를 고른다. 켤 센서가 없으면 조용히 0건을 보내지 않고 오류를 낸다.
func buildSensors(factory event.Factory, serverCfg transport.ServerConfig, opts options, log *slog.Logger) ([]runtime.Sensor, error) {
	if opts.selfTest {
		return []runtime.Sensor{&sensor.SelfTest{
			Factory:  factory,
			Interval: opts.selfTestInterval,
			// 해시기를 붙여 두면 자체 점검이 sha256 경로까지 확인해 준다.
			Hasher: sensor.NewFileHasher(),
		}}, nil
	}
	sensors := platformSensors(factory, serverCfg, log)
	if len(sensors) == 0 {
		return nil, fmt.Errorf("%s 에서 켤 센서가 없다. 서버 설정에서 전부 껐거나 지원하지 않는 플랫폼이다", goruntime.GOOS)
	}
	return sensors, nil
}
