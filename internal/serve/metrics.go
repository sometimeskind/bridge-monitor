package serve

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/pb"
	"github.com/sometimeskind/bridge-monitor/internal/secrets"
)

// metrics holds the bridge gauges exported on /metrics.
type metrics struct {
	accountState     *prometheus.GaugeVec
	accountConnected prometheus.Gauge
	grpcUp           prometheus.Gauge
	imapLoginOK      prometheus.Gauge

	imapConsecFails int
	imapNextProbe   time.Time
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
		imapLoginOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_imap_login_ok",
			Help: "1 if an authenticated IMAP LOGIN against the local bridge listener succeeded on the last poll, else 0.",
		}),
	}
	reg.MustRegister(m.accountState, m.accountConnected, m.grpcUp, m.imapLoginOK)
	return m
}

// poll connects to the bridge, reads the user list, and updates the gauges. A
// failure to connect or list users sets bridge_grpc_up=0 and clears the per-user
// state so stale series do not linger.
func (m *metrics) poll(ctx context.Context, configPath, emailFile, imapPasswordFile string) {
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

	now := time.Now()
	if !m.imapNextProbe.IsZero() && now.Before(m.imapNextProbe) {
		slog.Debug("metrics poll: imap probe skipped (backoff)", "retry_in", m.imapNextProbe.Sub(now).Round(time.Second))
		m.imapLoginOK.Set(0)
	} else {
		ok := m.probeIMAP(ctx, c, emailFile, imapPasswordFile)
		m.imapLoginOK.Set(boolToFloat(ok))
		if ok {
			m.imapConsecFails = 0
			m.imapNextProbe = time.Time{}
		} else {
			m.imapConsecFails++
			m.imapNextProbe = now.Add(imapProbeBackoff(m.imapConsecFails))
			slog.Info("metrics poll: imap probe backing off", "consec_fails", m.imapConsecFails, "retry_in", m.imapNextProbe.Sub(now).Round(time.Second))
		}
	}
}

// probeIMAP runs an authenticated IMAP LOGIN/LOGOUT against the bridge's
// local listener, the only signal that distinguishes a de-authed session
// (which stays CONNECTED locally) from a healthy one. Any failure along the
// way — fetching the listener settings, reading the secrets, or the login
// itself — reports unhealthy rather than failing the whole poll.
func (m *metrics) probeIMAP(ctx context.Context, c *bridge.Client, emailFile, imapPasswordFile string) bool {
	port, useSSL, err := c.MailServerSettings(ctx)
	if err != nil {
		slog.Warn("metrics poll: MailServerSettings failed", "err", err)
		return false
	}
	email, err := secrets.Read(emailFile)
	if err != nil {
		slog.Warn("metrics poll: read email file failed", "err", err)
		return false
	}
	password, err := secrets.Read(imapPasswordFile)
	if err != nil {
		slog.Warn("metrics poll: read imap password file failed", "err", err)
		return false
	}
	if err := bridge.ProbeIMAPLogin(ctx, port, useSSL, email, []byte(password)); err != nil {
		slog.Warn("metrics poll: imap login probe failed", "err", err)
		return false
	}
	return true
}

func (m *metrics) markDown() {
	m.grpcUp.Set(0)
	m.accountConnected.Set(0)
	m.imapLoginOK.Set(0)
	m.accountState.Reset()
}

// imapProbeBackoff returns the delay before the next IMAP probe after n
// consecutive failures: 30s → 1m → 2m → 4m, capped at 5m.
func imapProbeBackoff(n int) time.Duration {
	const base = 30 * time.Second
	const maxBackoff = 5 * time.Minute
	d := base * (1 << (n - 1))
	if d > maxBackoff || d <= 0 {
		return maxBackoff
	}
	return d
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// runPoller polls immediately and then on every tick until ctx is cancelled.
func (m *metrics) runPoller(ctx context.Context, configPath, emailFile, imapPasswordFile string, interval time.Duration) {
	pollOnce := func() {
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		m.poll(pctx, configPath, emailFile, imapPasswordFile)
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
