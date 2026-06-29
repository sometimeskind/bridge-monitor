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

// runStreamSubscriber maintains a persistent RunEventStream subscription,
// reconnecting on error until ctx is cancelled.
func runStreamSubscriber(ctx context.Context, configPath string, s *streamState, m *metrics) {
	fails := 0
	for {
		if ctx.Err() != nil {
			return
		}
		if err := streamOnce(ctx, configPath, s, m); err != nil {
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
func streamOnce(ctx context.Context, configPath string, s *streamState, m *metrics) error {
	c, err := bridge.Connect(configPath)
	if err != nil {
		return err
	}
	defer c.Close()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.Bridge.RunEventStream(streamCtx, &pb.EventStreamRequest{ClientPlatform: "bridge-monitor"})
	if err != nil {
		return err
	}
	defer func() { _, _ = c.Bridge.StopEventStream(context.WithoutCancel(ctx), &emptypb.Empty{}) }()

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
