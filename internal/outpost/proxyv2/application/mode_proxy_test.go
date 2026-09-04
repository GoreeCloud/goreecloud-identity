package application

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"goauthentik.io/internal/outpost/proxyv2/constants"
	"goauthentik.io/internal/outpost/proxyv2/types"
)

func rewriteProxyRequest(a *Application, upstream *url.URL, inbound *http.Request) *http.Request {
	outbound := inbound.Clone(inbound.Context())
	a.proxyRewriteRequest(upstream)(&httputil.ProxyRequest{In: inbound, Out: outbound})
	return outbound
}

func TestProxy_ModifyRequest(t *testing.T) {
	a := newTestApplication()
	req, _ := http.NewRequest("GET", "http://frontend/foo", nil)
	u, err := url.Parse("http://backend:8012")
	if err != nil {
		panic(err)
	}
	outbound := rewriteProxyRequest(a, u, req)

	assert.Equal(t, "frontend", outbound.Header.Get("X-Forwarded-Host"))
	assert.Equal(t, "http", outbound.Header.Get("X-Forwarded-Proto"))
	assert.Equal(t, "/foo", outbound.URL.Path)
	assert.Equal(t, "backend:8012", outbound.URL.Host)
	assert.Equal(t, "frontend", outbound.Host)
}

func TestProxy_Redirect(t *testing.T) {
	a := newTestApplication()
	_ = a.configureProxy()
	req, _ := http.NewRequest("GET", "https://ext.t.goauthentik.io/foo", nil)
	rr := httptest.NewRecorder()

	a.mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc, _ := rr.Result().Location()
	assert.Equal(
		t,
		"https://ext.t.goauthentik.io/outpost.goauthentik.io/start?rd=https%3A%2F%2Fext.t.goauthentik.io%2Ffoo",
		loc.String(),
	)
}

func TestProxy_Redirect_Subdirectory(t *testing.T) {
	a := newTestApplication()
	a.proxyConfig.ExternalHost = a.proxyConfig.ExternalHost + "/subdir"
	_ = a.configureProxy()
	req, _ := http.NewRequest("GET", "https://ext.t.goauthentik.io/foo", nil)
	rr := httptest.NewRecorder()

	a.mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc, _ := rr.Result().Location()
	assert.Equal(
		t,
		"https://ext.t.goauthentik.io/subdir/outpost.goauthentik.io/start?rd=https%3A%2F%2Fext.t.goauthentik.io%2Fsubdir%2Ffoo",
		loc.String(),
	)
}

func TestProxy_ModifyRequest_Claims(t *testing.T) {
	a := newTestApplication()
	req, _ := http.NewRequest("GET", "http://frontend/foo", nil)
	u, err := url.Parse("http://backend:8012")
	if err != nil {
		panic(err)
	}
	rr := httptest.NewRecorder()

	s, _ := a.sessions.Get(req, a.SessionName())
	s.ID = uuid.New().String()
	s.Options.MaxAge = 86400
	s.Values[constants.SessionClaims] = types.Claims{
		Sub: "foo",
		Proxy: &types.ProxyClaims{
			BackendOverride: "http://other-backend:8123",
		},
	}
	err = a.sessions.Save(req, rr, s)
	if err != nil {
		panic(err)
	}

	outbound := rewriteProxyRequest(a, u, req)

	assert.Equal(t, "/foo", outbound.URL.Path)
	assert.Equal(t, "other-backend:8123", outbound.URL.Host)
	assert.Equal(t, "frontend", outbound.Host)
}

func TestProxy_ModifyRequest_Claims_Invalid(t *testing.T) {
	a := newTestApplication()
	req, _ := http.NewRequest("GET", "http://frontend/foo", nil)
	u, err := url.Parse("http://backend:8012")
	if err != nil {
		panic(err)
	}
	rr := httptest.NewRecorder()

	s, _ := a.sessions.Get(req, a.SessionName())
	s.ID = uuid.New().String()
	s.Options.MaxAge = 86400
	s.Values[constants.SessionClaims] = types.Claims{
		Sub: "foo",
		Proxy: &types.ProxyClaims{
			BackendOverride: ":qewr",
		},
	}
	err = a.sessions.Save(req, rr, s)
	if err != nil {
		panic(err)
	}

	outbound := rewriteProxyRequest(a, u, req)

	assert.Equal(t, "/foo", outbound.URL.Path)
	assert.Equal(t, "backend:8012", outbound.URL.Host)
	assert.Equal(t, "frontend", outbound.Host)
}
