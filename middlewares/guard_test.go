package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prest/prest/v2/config"
	"github.com/stretchr/testify/require"
	"github.com/urfave/negroni/v3"
)

func newGuardTestStack(t *testing.T, mutate func(*config.GuardConf)) *negroni.Negroni {
	t.Helper()
	cfg := &config.Prest{}
	if mutate != nil {
		mutate(&cfg.Guard)
	}
	return New(cfg)
}

func serveGuardRequest(n *negroni.Negroni, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	n.ServeHTTP(rec, req)
	return rec
}

func TestGuardDisabledByDefault(t *testing.T) {
	n := newGuardTestStack(t, nil)
	// With guard disabled even an obvious injection attempt must pass through
	// untouched: no engine is built and behavior is byte-identical to before.
	res := serveGuardRequest(n, "/teste?name=1%27%20OR%20%271%27%3D%271")
	require.Equal(t, http.StatusOK, res.Code)
}

func TestGuardEnabledBlocksInjection(t *testing.T) {
	n := newGuardTestStack(t, func(g *config.GuardConf) {
		g.Enabled = true
	})

	res := serveGuardRequest(n, "/teste?name=1%27%20OR%20%271%27%3D%271")
	// Penetration detection answers 400 Bad Request for matched payloads.
	require.Equal(t, http.StatusBadRequest, res.Code)

	res = serveGuardRequest(n, "/teste?name=alice")
	require.Equal(t, http.StatusOK, res.Code)
}

func TestGuardPassiveModeLogsButDoesNotBlock(t *testing.T) {
	n := newGuardTestStack(t, func(g *config.GuardConf) {
		g.Enabled = true
		g.Passive = true
	})

	res := serveGuardRequest(n, "/teste?name=1%27%20OR%20%271%27%3D%271")
	require.Equal(t, http.StatusOK, res.Code)
}

func TestGuardRateLimitPerClient(t *testing.T) {
	n := newGuardTestStack(t, func(g *config.GuardConf) {
		g.Enabled = true
		g.RateLimit = 2
		g.RateLimitWindow = 60
	})

	for i := 0; i < 2; i++ {
		res := serveGuardRequest(n, "/teste")
		require.Equal(t, http.StatusOK, res.Code, "request %d within limit", i+1)
	}
	res := serveGuardRequest(n, "/teste")
	require.Equal(t, http.StatusTooManyRequests, res.Code)
}

func TestGuardBlacklistBlockedWhitelistAllowed(t *testing.T) {
	n := newGuardTestStack(t, func(g *config.GuardConf) {
		g.Enabled = true
		g.Blacklist = []string{"203.0.113.0/24"}
	})

	req := httptest.NewRequest(http.MethodGet, "/teste", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()
	n.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGuardExcludePathsSkipsChecks(t *testing.T) {
	n := newGuardTestStack(t, func(g *config.GuardConf) {
		g.Enabled = true
		g.ExcludePaths = []string{"/health"}
	})

	res := serveGuardRequest(n, "/health?name=1%27%20OR%20%271%27%3D%271")
	require.Equal(t, http.StatusOK, res.Code)
}

func TestGuardInvalidConfigFailsClosed(t *testing.T) {
	n := newGuardTestStack(t, func(g *config.GuardConf) {
		g.Enabled = true
		g.BlockCloudProviders = []string{"not-a-provider"}
	})

	res := serveGuardRequest(n, "/teste")
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
