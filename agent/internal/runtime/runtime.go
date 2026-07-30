// Package runtime 은 센서와 전송을 잇는다.
//
// 센서는 각자 고루틴에서 돌며 채널로 이벤트를 흘리고, 런타임이 그걸 버퍼에 모아
// 주기적으로 서버에 보낸다. 센서가 전송을 직접 하지 않는 이유는 서버가 잠깐 죽어도
// 커널 이벤트 구독이 멈추면 안 되기 때문이다. 그 사이 이벤트는 버퍼가 받아 준다.
package runtime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// Sensor 는 이벤트를 만들어 내는 관찰 지점 하나다.
// Run 은 ctx 가 끝날 때까지 막혀 있어야 하고, 끝나면 ctx.Err() 를 돌려준다.
type Sensor interface {
	Name() string
	Run(ctx context.Context, out chan<- event.Event) error
}

// Sender 는 이벤트 배치를 서버로 보낸다. transport.Client 가 이걸 만족한다.
type Sender interface {
	SendEvents(ctx context.Context, events []event.Event) error
}

// Options 는 런타임 동작을 조절한다. 0 이면 기본값을 쓴다.
type Options struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
	Logger        *slog.Logger
}

// Runtime 은 센서 묶음을 돌리고 모인 이벤트를 흘려보낸다.
type Runtime struct {
	sender Sender
	buf    *event.Buffer
	opts   Options
	log    *slog.Logger
}

// New 는 런타임을 만든다.
func New(sender Sender, opts Options) *Runtime {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 10000
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 500
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 5 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Runtime{
		sender: sender,
		buf:    event.NewBuffer(opts.BufferSize),
		opts:   opts,
		log:    opts.Logger,
	}
}

// Buffer 는 센서가 이벤트를 넣는 버퍼다.
func (r *Runtime) Buffer() *event.Buffer { return r.buf }

// Flush 는 버퍼에서 한 배치를 꺼내 보낸다.
// 실패하면 배치를 버퍼 앞으로 되돌리고 오류를 올린다. 되돌리지 않으면 그 이벤트는 사라진다.
func (r *Runtime) Flush(ctx context.Context) error {
	batch := r.buf.Drain(r.opts.BatchSize)
	if len(batch) == 0 {
		return nil
	}
	if err := r.sender.SendEvents(ctx, batch); err != nil {
		r.buf.Requeue(batch)
		return err
	}
	return nil
}

// Run 은 센서를 모두 띄우고 주기마다 Flush 한다.
// ctx 가 끝나면 센서를 멈추고 남은 이벤트를 마지막으로 흘려보낸 뒤 nil 을 돌려준다.
// 종료는 정상 동작이므로 오류로 올리지 않는다.
func (r *Runtime) Run(ctx context.Context, sensors []Sensor) error {
	events := make(chan event.Event, r.opts.BatchSize)
	sensorCtx, stopSensors := context.WithCancel(ctx)
	defer stopSensors()

	for _, s := range sensors {
		go func(s Sensor) {
			if err := s.Run(sensorCtx, events); err != nil && !errors.Is(err, context.Canceled) {
				r.log.Error("센서가 멈췄다", "sensor", s.Name(), "err", err)
			}
		}(s)
	}

	ticker := time.NewTicker(r.opts.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case e := <-events:
			r.buf.Add(e)
		case <-ticker.C:
			r.flushLogged(ctx)
		case <-ctx.Done():
			stopSensors()
			r.drainChannel(events)
			// 종료 직전 남은 이벤트까지 보낸다. ctx 는 이미 끝났으므로 새 시한을 준다.
			shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.opts.FlushInterval)
			defer cancel()
			r.flushLogged(shutdown)
			return nil
		}
	}
}

// drainChannel 은 센서가 이미 채널에 넣어 둔 이벤트를 버퍼로 옮긴다.
func (r *Runtime) drainChannel(events <-chan event.Event) {
	for {
		select {
		case e := <-events:
			r.buf.Add(e)
		default:
			return
		}
	}
}

// flushLogged 는 Flush 하고 실패는 기록만 한다.
// 배치가 버퍼에 되돌아가 있으므로 다음 주기에 다시 시도된다.
func (r *Runtime) flushLogged(ctx context.Context) {
	if err := r.Flush(ctx); err != nil {
		r.log.Warn("전송 실패, 다음 주기에 재시도", "err", err, "buffered", r.buf.Len(), "dropped", r.buf.Dropped())
	}
}
