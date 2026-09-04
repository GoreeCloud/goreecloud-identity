package application

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"goauthentik.io/internal/outpost/proxyv2/metrics"
	"goauthentik.io/internal/utils/web"
)

func (a *Application) getUpstreamTransport() http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !*a.proxyConfig.InternalHostSslValidation},
	}
}

func (a *Application) configureProxy() error {
	// Reverse proxy to the application server
	u, err := url.Parse(*a.proxyConfig.InternalHost)
	if err != nil {
		return err
	}
	rsp := sentry.StartSpan(context.TODO(), "authentik.outposts.proxy.application_transport")
	rp := &httputil.ReverseProxy{
		Rewrite:        a.proxyRewriteRequest(u),
		Transport:      web.NewTracingTransport(rsp.Context(), a.getUpstreamTransport()),
		ErrorHandler:   a.newProxyErrorHandler(),
		ModifyResponse: a.proxyModifyResponse,
		FlushInterval:  -1,
	}
	a.mux.PathPrefix("/").HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err == nil || err == http.ErrAbortHandler {
				return
			}
			log.WithError(err.(error)).Error("recover in reverse proxy")
		}()
		claims, err := a.checkAuth(rw, r)
		if claims == nil && a.IsAllowlisted(r.URL) {
			a.log.Trace("path can be accessed without authentication")
		} else if claims == nil && err != nil {
			a.log.WithError(err).Trace("no claims")
			a.redirectToStart(rw, r)
			return
		} else {
			a.addHeaders(r.Header, claims)
		}
		before := time.Now()
		rp.ServeHTTP(rw, r)
		elapsed := time.Since(before)

		metrics.UpstreamTiming.With(prometheus.Labels{
			"outpost_name":  a.outpostName,
			"upstream_host": r.URL.Host,
			"method":        r.Method,
			"scheme":        r.URL.Scheme,
			"host":          web.GetHost(r),
		}).Observe(float64(elapsed) / float64(time.Second))
	})
	return nil
}

func (a *Application) proxyRewriteRequest(ou *url.URL) func(req *httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		r := pr.Out
		r.URL.Scheme = ou.Scheme
		r.URL.Host = ou.Host

		// Rewrite runs after hop-by-hop and client-supplied Forwarded headers are
		// removed. Recreate forwarding metadata from the actual inbound request so
		// a client cannot erase or spoof proxy-added forwarding headers.
		pr.SetXForwarded()

		claims := a.getClaimsFromSession(nil, pr.In)
		if claims != nil && claims.Proxy != nil {
			if claims.Proxy.BackendOverride != "" {
				u, err := url.Parse(claims.Proxy.BackendOverride)
				if err != nil {
					a.log.WithField("backend_override", claims.Proxy.BackendOverride).WithError(err).Warning("failed parse user backend override")
				} else {
					r.URL.Scheme = u.Scheme
					r.URL.Host = u.Host
				}
			}
			if claims.Proxy.HostHeader != "" {
				r.Host = claims.Proxy.HostHeader
			}
		}
		a.log.WithField("upstream_url", r.URL.String()).Trace("final upstream url")
	}
}

func (a *Application) proxyModifyResponse(res *http.Response) error {
	res.Header.Set("X-Powered-By", "goauthentik.io")
	return nil
}
