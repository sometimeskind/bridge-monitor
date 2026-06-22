package serve

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// metrics holds the bridge gauges exported on /metrics.
type metrics struct {
	accountState     *prometheus.GaugeVec
	accountConnected prometheus.Gauge
	grpcUp           prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		accountState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bridge_account_state",
			Help: "Bridge account state (0=SIGNED_OUT, 1=LOCKED, 2=CONNECTED).",
		}, []string{"user", "email"}),
		accountConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_account_connected",
			Help: "1 if any bridge user is CONNECTED, else 0.",
		}),
		grpcUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_grpc_up",
			Help: "1 if the bridge gRPC API answered the last poll, else 0.",
		}),
	}
	reg.MustRegister(m.accountState, m.accountConnected, m.grpcUp)
	return m
}

// poll connects to the bridge, reads the user list, and updates the gauges. A
// failure to connect or list users sets bridge_grpc_up=0 and clears the per-user
// state so stale series do not linger.
func (m *metrics) poll(ctx context.Context, configPath string) {
	c, err := bridge.Connect(configPath)
	if err != nil {
		m.markDown()
		slog.Warn("metrics poll: connect failed", "err", err)
		return
	}
	defer c.Close()

	users, err := c.GetUsers(ctx)
	if err != nil {
		m.markDown()
		slog.Warn("metrics poll: GetUserList failed", "err", err)
		return
	}

	m.grpcUp.Set(1)
	m.accountState.Reset()
	anyConnected := false
	for _, u := range users {
		email := ""
		if addrs := u.GetAddresses(); len(addrs) > 0 {
			email = addrs[0]
		}
		m.accountState.WithLabelValues(u.GetUsername(), email).Set(float64(u.GetState()))
		if u.GetState() == pb.UserState_CONNECTED {
			anyConnected = true
		}
	}
	m.accountConnected.Set(boolToFloat(anyConnected))
}

func (m *metrics) markDown() {
	m.grpcUp.Set(0)
	m.accountConnected.Set(0)
	m.accountState.Reset()
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// runPoller polls immediately and then on every tick until ctx is cancelled.
func (m *metrics) runPoller(ctx context.Context, configPath string, interval time.Duration) {
	pollOnce := func() {
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		m.poll(pctx, configPath)
	}
	pollOnce()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollOnce()
		}
	}
}
