package middlewares

import (
	"fmt"
	"net/http"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
	nethttpguard "github.com/rennf93/nethttp-guard"
	"github.com/urfave/negroni/v3"

	"github.com/prest/prest/v2/config"
)

// GuardMiddleware wraps the request chain with the guard-core engine
// (per-client rate limits, request payload inspection, IP policy). The
// middleware sits after CORS so blocked responses keep CORS headers, and
// before JWT auth so the auth endpoint is covered by rate limits.
//
// Opt-in via [guard] config (PREST_GUARD_* env vars); DisabledByDefault means
// New() never builds an engine unless guard.enabled is true.
func GuardMiddleware(conf config.GuardConf) (negroni.Handler, error) {
	engineCfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = conf.RedisURL != ""
		c.RedisURL = conf.RedisURL
		c.RedisPrefix = conf.RedisPrefix
		c.RedisFailOpen = true

		c.PassiveMode = conf.Passive
		c.EnableRateLimiting = conf.RateLimit > 0
		if conf.RateLimit > 0 {
			c.RateLimit = conf.RateLimit
			c.RateLimitWindow = conf.RateLimitWindow
		}
		c.EnablePenetrationDetection = true
		c.EnableIPBanning = !conf.Passive

		c.Whitelist = conf.Whitelist
		c.Blacklist = conf.Blacklist
		c.BlockCloudProviders = conf.BlockCloudProviders
		if len(conf.ExcludePaths) > 0 {
			c.ExcludePaths = conf.ExcludePaths
		}
	})
	if err != nil {
		return nil, fmt.Errorf("guard config invalid: %w", err)
	}

	engine, err := guardcore.NewEngine(engineCfg)
	if err != nil {
		return nil, fmt.Errorf("guard engine init failed: %w", err)
	}
	if err = engine.Initialize(); err != nil {
		return nil, fmt.Errorf("guard engine startup failed: %w", err)
	}

	wrap, err := nethttpguard.New(engine, nethttpguard.WithMaxBodyBytes(conf.MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("guard middleware init failed: %w", err)
	}

	return negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		wrap(next).ServeHTTP(w, r)
	}), nil
}

// invalidGuardConfigMiddleware responds 500 to every request when the guard
// was explicitly enabled but its config is unusable: a security layer the
// operator asked for must never silently degrade to absent.
func invalidGuardConfigMiddleware(err error) negroni.Handler {
	return negroni.HandlerFunc(func(w http.ResponseWriter, _ *http.Request, _ http.HandlerFunc) {
		http.Error(w, fmt.Sprintf(jsonErrFormat, err.Error()), http.StatusInternalServerError)
	})
}
