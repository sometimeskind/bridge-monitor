package serve

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// streamState holds the most recent values received from RunEventStream. The
// write lock is held by the subscriber goroutine; read locks are held by the
// metrics scrape path and HTTP handler.
type streamState struct {
	mu              sync.RWMutex
	internetOK      bool
	lastBadEvent    time.Time
	lastBadEventMsg string
	updateVersion   string // empty = no update seen
	updateForced    bool
	usedBytes       int64
}

// streamSnapshot is a lock-free copy of streamState for passing to templates.
type streamSnapshot struct {
	InternetOK      bool
	LastBadEvent    time.Time
	LastBadEventMsg string
	HasBadEvent     bool
	UpdateVersion   string
	UpdateForced    bool
	UsedBytes       int64
}

func (s *streamState) snapshot() streamSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return streamSnapshot{
		InternetOK:      s.internetOK,
		LastBadEvent:    s.lastBadEvent,
		LastBadEventMsg: s.lastBadEventMsg,
		HasBadEvent:     !s.lastBadEvent.IsZero(),
		UpdateVersion:   s.updateVersion,
		UpdateForced:    s.updateForced,
		UsedBytes:       s.usedBytes,
	}
}

// subscriberCtrl manages the background RunEventStream subscriber goroutine so
// the web handler can pause it cleanly before a re-auth attempt.
//
// The race it prevents: Login calls StopEventStream then RunEventStream. If the
// subscriber's streamOnce is still alive, StopEventStream kills its stream,
// streamOnce returns, and its deferred StopEventStream fires — which then kills
// Login's newly-opened stream. By pausing (cancel + wait-for-exit) first, the
// subscriber's defer has already run by the time Login calls RunEventStream.
type subscriberCtrl struct {
	parentCtx  context.Context
	configPath string
	grpcHost   string
	ss         *streamState
	m          *metrics

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func newSubscriberCtrl(parentCtx context.Context, configPath, grpcHost string, ss *streamState, m *metrics) *subscriberCtrl {
	sc := &subscriberCtrl{
		parentCtx:  parentCtx,
		configPath: configPath,
		grpcHost:   grpcHost,
		ss:         ss,
		m:          m,
	}
	sc.launch()
	return sc
}

func (sc *subscriberCtrl) launch() {
	ctx, cancel := context.WithCancel(sc.parentCtx)
	done := make(chan struct{})
	sc.mu.Lock()
	sc.cancel = cancel
	sc.done = done
	sc.mu.Unlock()
	go func() {
		defer close(done)
		runStreamSubscriber(ctx, sc.configPath, sc.grpcHost, sc.ss, sc.m)
	}()
}

// pause cancels the subscriber's context and blocks until the goroutine has
// fully exited, including its deferred StopEventStream call. Must not be
// called concurrently with another pause.
//
// When the bridge is slow (e.g. in a de-authed state), context cancellation
// alone may not unblock stream.Recv() quickly. pause also sends StopEventStream
// directly so the bridge closes the stream immediately, and falls back to a 5s
// timeout if the goroutine still has not exited after that.
func (sc *subscriberCtrl) pause() {
	sc.mu.Lock()
	cancel := sc.cancel
	done := sc.done
	sc.mu.Unlock()
	cancel()

	// Proactively tell the bridge to close the active stream. This unblocks
	// the subscriber's stream.Recv() faster than waiting for gRPC to propagate
	// context cancellation through a slow or degraded bridge.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if c, err := bridge.Connect(sc.configPath, sc.grpcHost); err == nil {
		_, _ = c.Bridge.StopEventStream(stopCtx, &emptypb.Empty{})
		c.Close()
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("subscriber goroutine did not exit within 5s; proceeding with reauth")
	}
}

// resume launches a fresh subscriber goroutine. Must be called after pause.
func (sc *subscriberCtrl) resume() {
	sc.launch()
}

// waitForShutdown blocks until parentCtx is done and the current subscriber
// goroutine has exited. Used by the serve errgroup for clean shutdown.
func (sc *subscriberCtrl) waitForShutdown() {
	<-sc.parentCtx.Done()
	sc.mu.Lock()
	done := sc.done
	sc.mu.Unlock()
	<-done
}

// runStreamSubscriber maintains a persistent RunEventStream subscription,
// reconnecting on error until ctx is cancelled.
func runStreamSubscriber(ctx context.Context, configPath, grpcHost string, s *streamState, m *metrics) {
	fails := 0
	for {
		if ctx.Err() != nil {
			return
		}
		if err := streamOnce(ctx, configPath, grpcHost, s, m); err != nil {
			if ctx.Err() != nil {
				return
			}
			fails++
			backoff := imapProbeBackoff(fails)
			slog.Warn("event stream: disconnected, reconnecting", "err", err, "backoff", backoff.Round(time.Second))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		} else {
			fails = 0
		}
	}
}

// streamOnce opens one RunEventStream connection and reads events until error.
func streamOnce(ctx context.Context, configPath, grpcHost string, s *streamState, m *metrics) error {
	c, err := bridge.Connect(configPath, grpcHost)
	if err != nil {
		return err
	}
	defer c.Close()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Always stop the stream on exit, even if RunEventStream itself failed with
	// AlreadyExists. Without this, a lingering stream on Bridge's side would
	// prevent every subsequent RunEventStream from succeeding.
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		_, _ = c.Bridge.StopEventStream(stopCtx, &emptypb.Empty{})
	}()

	stream, err := c.Bridge.RunEventStream(streamCtx, &pb.EventStreamRequest{ClientPlatform: "bridge-monitor"})
	if err != nil {
		return err
	}

	slog.Info("event stream: connected")
	for {
		evt, err := stream.Recv()
		if err != nil {
			return err
		}
		applyStreamEvent(evt, s, m)
	}
}

// applyStreamEvent updates streamState and Prometheus metrics for one received event.
func applyStreamEvent(evt *pb.StreamEvent, s *streamState, m *metrics) {
	if app := evt.GetApp(); app != nil {
		if is := app.GetInternetStatus(); is != nil {
			connected := is.GetConnected()
			s.mu.Lock()
			s.internetOK = connected
			s.mu.Unlock()
			m.internetConnected.Set(boolToFloat(connected))
			return
		}
	}
	if upd := evt.GetUpdate(); upd != nil {
		if mr := upd.GetManualReady(); mr != nil {
			s.mu.Lock()
			s.updateVersion = mr.GetVersion()
			s.updateForced = false
			s.mu.Unlock()
			m.updateAvailable.Set(1)
			return
		}
		if f := upd.GetForce(); f != nil {
			s.mu.Lock()
			s.updateVersion = f.GetVersion()
			s.updateForced = true
			s.mu.Unlock()
			m.updateAvailable.Set(2)
			slog.Warn("event stream: forced update", "version", f.GetVersion())
			return
		}
	}
	if user := evt.GetUser(); user != nil {
		if bad := user.GetUserBadEvent(); bad != nil {
			now := time.Now()
			s.mu.Lock()
			s.lastBadEvent = now
			s.lastBadEventMsg = bad.GetErrorMessage()
			s.mu.Unlock()
			m.badEventsTotal.Inc()
			m.lastBadEventTs.Set(float64(now.Unix()))
			slog.Warn("event stream: user bad event", "error", bad.GetErrorMessage())
			return
		}
		if ub := user.GetUsedBytesChangedEvent(); ub != nil {
			s.mu.Lock()
			s.usedBytes = ub.GetUsedBytes()
			s.mu.Unlock()
			m.usedBytes.Set(float64(ub.GetUsedBytes()))
			return
		}
		if imap := user.GetImapLoginFailedEvent(); imap != nil {
			m.imapLoginFailedTotal.Inc()
			slog.Warn("event stream: IMAP login failed", "username", imap.GetUsername())
			return
		}
	}
}
