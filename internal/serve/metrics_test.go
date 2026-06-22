package serve

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// When the bridge config is unreachable, the poll must report bridge_grpc_up=0
// rather than crashing.
func TestPollMarksDownOnBadConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	m.poll(context.Background(), "/nonexistent/grpcServerConfig.json")

	if got := testutil.ToFloat64(m.grpcUp); got != 0 {
		t.Errorf("bridge_grpc_up = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.accountConnected); got != 0 {
		t.Errorf("bridge_account_connected = %v, want 0", got)
	}
}
