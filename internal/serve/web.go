package serve

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sometimeskind/bridge-monitor/internal/reauth"
	"github.com/sometimeskind/bridge-monitor/internal/secrets"
	"github.com/sometimeskind/bridge-monitor/internal/totp"
)

// loginTimeout bounds a single re-auth attempt so a missing event cannot hang
// the HTTP request.
const loginTimeout = 60 * time.Second

// webHandler serves the re-auth form and drives the login flow. Attempts are
// serialized: the bridge holds a single in-flight login state server-side, so
// two concurrent re-auths would clobber each other.
type webHandler struct {
	cfg          reauth.Config
	emailFile    string
	totpSeedFile string
	tmpl         *template.Template
	mu           sync.Mutex
}

func newWebHandler(cfg reauth.Config, emailFile, totpSeedFile string) *webHandler {
	return &webHandler{
		cfg:          cfg,
		emailFile:    emailFile,
		totpSeedFile: totpSeedFile,
		tmpl:         template.Must(template.New("web").Parse(webTemplates)),
	}
}

func (h *webHandler) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.handleForm)
	mux.HandleFunc("POST /auth", h.handleAuth)
}

func (h *webHandler) handleForm(w http.ResponseWriter, _ *http.Request) {
	email, err := secrets.Read(h.emailFile)
	if err != nil {
		slog.Warn("could not read email file for form prefill", "err", err)
	}
	h.render(w, "form", map[string]any{"Email": email})
}

func (h *webHandler) handleAuth(w http.ResponseWriter, r *http.Request) {
	// CSRF defence: reject cross-site POSTs. Without this, a page open in the
	// operator's (gateway-reachable) browser could forge failed logins and
	// trigger a Proton-side account lockout. Authentication is intentionally
	// delegated to the private gateway; this only blocks forged origins.
	if !sameOrigin(r) {
		h.render(w, "result", resultData{Error: "request rejected: cross-site origin"})
		return
	}
	if err := r.ParseForm(); err != nil {
		h.render(w, "result", resultData{Error: "invalid form submission"})
		return
	}
	password := r.PostFormValue("password")
	if password == "" {
		h.render(w, "result", resultData{Error: "password is required"})
		return
	}

	email, err := secrets.Read(h.emailFile)
	if err != nil {
		slog.Error("read email file", "err", err)
		h.render(w, "result", resultData{Error: "server misconfiguration: cannot read email"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	code, err := totp.FromSeedFile(h.totpSeedFile)
	if err != nil {
		slog.Error("generate TOTP", "err", err)
		h.render(w, "result", resultData{Error: "server misconfiguration: cannot generate 2FA code"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), loginTimeout)
	defer cancel()

	out, err := reauth.Run(ctx, h.cfg, email, []byte(password), code)
	if err != nil {
		slog.Warn("reauth failed", "email", email, "err", err)
		h.render(w, "result", resultData{Email: email, Error: err.Error()})
		return
	}

	slog.Info("reauth succeeded", "email", email, "imap_changed", out.Changed)
	data := resultData{
		Email:        email,
		Success:      true,
		IMAPPassword: out.IMAPPassword,
		Changed:      out.Changed,
	}
	if out.CompareError != nil {
		data.CompareWarning = "could not compare against the sealed IMAP password; verify manually"
	}
	h.render(w, "result", data)
}

type resultData struct {
	Email          string
	Success        bool
	Error          string
	IMAPPassword   string
	Changed        bool
	CompareWarning string
}

// sameOrigin reports whether a POST is same-origin. Browsers always send Origin
// on cross-origin form submissions, so a present-but-mismatched Origin is a
// cross-site request. A missing Origin (non-browser clients such as curl) is
// allowed, since the private gateway remains the primary access control.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

func (h *webHandler) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The result page contains the IMAP password; keep it out of browser and
	// intermediary caches (and out of the back-button cache).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

const webTemplates = `
{{define "form"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bridge re-auth</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}
label{display:block;margin:.75rem 0 .25rem}input{width:100%;padding:.5rem;font-size:1rem}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem}</style></head>
<body><h1>Proton Bridge re-auth</h1>
<form method="post" action="/auth">
<label for="email">Email</label>
<input id="email" name="email" type="email" value="{{.Email}}" readonly>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit">Re-authenticate</button>
</form></body></html>{{end}}

{{define "result"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bridge re-auth result</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}
code{display:block;padding:.5rem;background:#f3f3f3;word-break:break-all}
.warn{background:#fff3cd;padding:.75rem;border-radius:.25rem}
.err{background:#f8d7da;padding:.75rem;border-radius:.25rem}</style></head>
<body>
{{if .Success}}
<h1>Re-authentication succeeded</h1>
<p>Logged in as {{.Email}}.</p>
{{if .Changed}}<div class="warn"><strong>IMAP password changed.</strong>
Re-seal this value in the homelab repo:</div>{{else}}<p>IMAP password unchanged.</p>{{end}}
<p>IMAP password:</p><code>{{.IMAPPassword}}</code>
{{if .CompareWarning}}<div class="warn">{{.CompareWarning}}</div>{{end}}
{{else}}
<h1>Re-authentication failed</h1>
<div class="err">{{.Error}}</div>
{{end}}
<p><a href="/">Back</a></p>
</body></html>{{end}}
`
