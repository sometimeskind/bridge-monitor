package serve

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sometimeskind/bridge-monitor/internal/bridge"
	"github.com/sometimeskind/bridge-monitor/internal/pb"
	"github.com/sometimeskind/bridge-monitor/internal/secrets"
)

// metrics holds the bridge gauges exported on /metrics.
type metrics struct {
	// poll-derived
	accountState     *prometheus.GaugeVec
	accountConnected prometheus.Gauge
	grpcUp           prometheus.Gauge
	imapLoginOK      prometheus.Gauge

	imapConsecFails int
	imapNextProbe   time.Time

	// stream-derived
	internetConnected    prometheus.Gauge
	badEventsTotal       prometheus.Counter
	lastBadEventTs       prometheus.Gauge
	updateAvailable      prometheus.Gauge
	usedBytes            prometheus.Gauge
	imapLoginFailedTotal prometheus.Counter
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
		internetConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_internet_connected",
			Help: "1 if Bridge can reach Proton's network (from RunEventStream InternetStatusEvent), else 0.",
		}),
		badEventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "bridge_bad_events_total",
			Help: "Total UserBadEvent messages received from Bridge (zombie de-auth indicator).",
		}),
		lastBadEventTs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_last_bad_event_timestamp_seconds",
			Help: "Unix timestamp of the most recent UserBadEvent; 0 if none seen since startup.",
		}),
		updateAvailable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_update_available",
			Help: "Bridge update state: 0=none, 1=manual update ready, 2=forced (Bridge will stop working).",
		}),
		usedBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bridge_used_bytes",
			Help: "Proton mailbox storage usage in bytes (from RunEventStream UsedBytesChangedEvent).",
		}),
		imapLoginFailedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "bridge_imap_login_failed_total",
			Help: "Total ImapLoginFailedEvent messages received from Bridge (local IMAP LOGIN rejections).",
		}),
	}
	reg.MustRegister(
		m.accountState, m.accountConnected, m.grpcUp, m.imapLoginOK,
		m.internetConnected, m.badEventsTotal, m.lastBadEventTs,
		m.updateAvailable, m.usedBytes, m.imapLoginFailedTotal,
	)
	// Seed optimistic default: the bridge only emits InternetStatusEvent on
	// change, so a healthy bridge that was already connected when the monitor
	// starts will never send one. Starting at 1 avoids a false-positive alert
	// while we wait for the first state-change event.
	m.internetConnected.Set(1)
	return m
}

// poll connects to the bridge, reads the user list, and updates the gauges. A
// failure to connect or list users sets bridge_grpc_up=0 and clears the per-user
// state so stale series do not linger.
func (m *metrics) poll(ctx context.Context, configPath, grpcHost, imapHost, emailFile, imapPasswordFile string) {
	c, err := bridge.Connect(configPath, grpcHost)
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
		ok := m.probeIMAP(ctx, c, imapHost, emailFile, imapPasswordFile)
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
// listener, the only signal that distinguishes a de-authed session (which
// stays CONNECTED locally) from a healthy one. Any failure along the way —
// fetching the listener settings, reading the secrets, or the login itself —
// reports unhealthy rather than failing the whole poll.
//
// When imapHost is non-empty it is used directly as the dial address (no TLS),
// skipping the MailServerSettings gRPC call. This supports cross-pod setups
// where the IMAP port is exposed via a socat ClusterIP proxy.
func (m *metrics) probeIMAP(ctx context.Context, c *bridge.Client, imapHost, emailFile, imapPasswordFile string) bool {
	var addr string
	var useSSL bool
	if imapHost != "" {
		addr = imapHost
	} else {
		port, ssl, err := c.MailServerSettings(ctx)
		if err != nil {
			slog.Warn("metrics poll: MailServerSettings failed", "err", err)
			return false
		}
		addr = fmt.Sprintf("127.0.0.1:%d", port)
		useSSL = ssl
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
	if err := bridge.ProbeIMAPLogin(ctx, addr, useSSL, email, []byte(password)); err != nil {
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
func (m *metrics) runPoller(ctx context.Context, configPath, grpcHost, imapHost, emailFile, imapPasswordFile string, interval time.Duration) {
	pollOnce := func() {
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		m.poll(pctx, configPath, grpcHost, imapHost, emailFile, imapPasswordFile)
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
