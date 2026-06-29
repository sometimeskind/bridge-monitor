package serve

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

func TestApplyStreamEvent(t *testing.T) {
	tests := []struct {
		name    string
		evt     *pb.StreamEvent
		check   func(t *testing.T, s *streamState, m *metrics)
	}{
		{
			name: "internet connected",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_App{App: &pb.AppEvent{
				Event: &pb.AppEvent_InternetStatus{InternetStatus: &pb.InternetStatusEvent{Connected: true}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if !s.internetOK {
					t.Error("internetOK should be true")
				}
				if got := testutil.ToFloat64(m.internetConnected); got != 1 {
					t.Errorf("bridge_internet_connected = %v, want 1", got)
				}
			},
		},
		{
			name: "internet disconnected",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_App{App: &pb.AppEvent{
				Event: &pb.AppEvent_InternetStatus{InternetStatus: &pb.InternetStatusEvent{Connected: false}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if s.internetOK {
					t.Error("internetOK should be false")
				}
				if got := testutil.ToFloat64(m.internetConnected); got != 0 {
					t.Errorf("bridge_internet_connected = %v, want 0", got)
				}
			},
		},
		{
			name: "user bad event",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_User{User: &pb.UserEvent{
				Event: &pb.UserEvent_UserBadEvent{UserBadEvent: &pb.UserBadEvent{ErrorMessage: "auth-error"}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if s.lastBadEvent.IsZero() {
					t.Error("lastBadEvent should be set")
				}
				if s.lastBadEventMsg != "auth-error" {
					t.Errorf("lastBadEventMsg = %q, want %q", s.lastBadEventMsg, "auth-error")
				}
				if got := testutil.ToFloat64(m.badEventsTotal); got != 1 {
					t.Errorf("bridge_bad_events_total = %v, want 1", got)
				}
				if got := testutil.ToFloat64(m.lastBadEventTs); got == 0 {
					t.Error("bridge_last_bad_event_timestamp_seconds should be non-zero")
				}
			},
		},
		{
			name: "update manual ready",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_Update{Update: &pb.UpdateEvent{
				Event: &pb.UpdateEvent_ManualReady{ManualReady: &pb.UpdateManualReadyEvent{Version: "3.1.0"}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if s.updateVersion != "3.1.0" {
					t.Errorf("updateVersion = %q, want %q", s.updateVersion, "3.1.0")
				}
				if s.updateForced {
					t.Error("updateForced should be false for manual update")
				}
				if got := testutil.ToFloat64(m.updateAvailable); got != 1 {
					t.Errorf("bridge_update_available = %v, want 1", got)
				}
			},
		},
		{
			name: "update forced",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_Update{Update: &pb.UpdateEvent{
				Event: &pb.UpdateEvent_Force{Force: &pb.UpdateForceEvent{Version: "3.2.0"}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if s.updateVersion != "3.2.0" {
					t.Errorf("updateVersion = %q, want %q", s.updateVersion, "3.2.0")
				}
				if !s.updateForced {
					t.Error("updateForced should be true")
				}
				if got := testutil.ToFloat64(m.updateAvailable); got != 2 {
					t.Errorf("bridge_update_available = %v, want 2", got)
				}
			},
		},
		{
			name: "used bytes changed",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_User{User: &pb.UserEvent{
				Event: &pb.UserEvent_UsedBytesChangedEvent{UsedBytesChangedEvent: &pb.UsedBytesChangedEvent{UsedBytes: 5 << 30}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if s.usedBytes != 5<<30 {
					t.Errorf("usedBytes = %d, want %d", s.usedBytes, int64(5<<30))
				}
				if got := testutil.ToFloat64(m.usedBytes); got != float64(5<<30) {
					t.Errorf("bridge_used_bytes = %v, want %v", got, float64(5<<30))
				}
			},
		},
		{
			name: "imap login failed",
			evt: &pb.StreamEvent{Event: &pb.StreamEvent_User{User: &pb.UserEvent{
				Event: &pb.UserEvent_ImapLoginFailedEvent{ImapLoginFailedEvent: &pb.ImapLoginFailedEvent{Username: "test@example.com"}},
			}}},
			check: func(t *testing.T, s *streamState, m *metrics) {
				if got := testutil.ToFloat64(m.imapLoginFailedTotal); got != 1 {
					t.Errorf("bridge_imap_login_failed_total = %v, want 1", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m := newMetrics(reg)
			s := &streamState{}
			applyStreamEvent(tc.evt, s, m)
			tc.check(t, s, m)
		})
	}
}
