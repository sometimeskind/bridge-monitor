// Package serve runs the sidecar: Prometheus metrics plus the re-auth web UI.
package serve

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/sometimeskind/bridge-monitor/internal/reauth"
)

// Options configures the serve command.
type Options struct {
	GRPCConfigPath   string
	GRPCHost         string // non-empty → dial grpcHost:<port> over TCP (cross-pod)
	EmailFile        string
	IMAPHost         string // non-empty → dial this host:port directly, skipping MailServerSettings (cross-pod)
	IMAPPasswordFile string
	MetricsAddr      string // e.g. ":9100"
	WebAddr          string // e.g. ":8080"
	PollInterval     time.Duration
}

// Run starts the metrics poller, the metrics HTTP server, and the web UI, and
// blocks until ctx is cancelled or a server fails.
func Run(ctx context.Context, opts Options) error {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	ss := &streamState{}

	web := newWebHandler(reauth.Config{
		GRPCConfigPath:   opts.GRPCConfigPath,
		GRPCHost:         opts.GRPCHost,
		IMAPPasswordFile: opts.IMAPPasswordFile,
	}, opts.EmailFile, ss)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsSrv := &http.Server{Addr: opts.MetricsAddr, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}

	webMux := http.NewServeMux()
	web.routes(webMux)
	webSrv := &http.Server{Addr: opts.WebAddr, Handler: webMux, ReadHeaderTimeout: 5 * time.Second}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		m.runPoller(gctx, opts.GRPCConfigPath, opts.GRPCHost, opts.IMAPHost, opts.EmailFile, opts.IMAPPasswordFile, opts.PollInterval)
		return nil
	})
	g.Go(func() error {
		runStreamSubscriber(gctx, opts.GRPCConfigPath, opts.GRPCHost, ss, m)
		return nil
	})
	g.Go(func() error { return serveHTTP(gctx, metricsSrv, "metrics") })
	g.Go(func() error { return serveHTTP(gctx, webSrv, "web") })

	return g.Wait()
}

// serveHTTP runs srv and shuts it down gracefully when ctx is cancelled.
func serveHTTP(ctx context.Context, srv *http.Server, name string) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	slog.Info("listening", "server", name, "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
