// Copyright 2021 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package est

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"go.uber.org/zap"

	"github.com/oxtoacart/bpool"

	"github.com/globalsign/est"

	"github.com/hslatman/caddy-est/internal/ca"
	"github.com/hslatman/caddy-est/internal/logger"
)

func init() {
	caddy.RegisterModule(Handler{})
}

const (
	serverHeader = "Caddy EST Server v0.1.0"
)

// Handler is an EST server handler
type Handler struct {
	// CA is the ID of the Caddy PKI CA to use for issuing
	// certificates using EST
	CA string `json:"ca,omitempty"`
	// AllowedHosts are the allowed hosts (according to Host header)
	// that can use the CA for issuing certificates. Defaults to
	// an empty list, resulting in no host validation being
	// performed.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// RateLimit is the maximum number of requests per second
	// on handler level (so, for all clients together). Defaults
	// to 0, meaning no limit is enforced.
	RateLimit int `json:"rate_limit,omitempty"`
	// EnableBasicAuth enables HTTP Basic Authentication for
	// all EST endpoints
	EnableBasicAuth *bool `json:"enable_basic_auth,omitempty"`
	// BasicAuthUsername is the username to use for HTTP Basic
	// authentication
	BasicAuthUsername string `json:"basic_auth_username,omitempty"`
	// BasicAuthPassword is the password to use for HTTP Basic
	// authentication
	BasicAuthPassword string `json:"basic_auth_password,omitempty"`

	// TODO: improve the Basic Auth configuration?
	// TODO: think about and implement alternative methods for authentication.

	logger     *zap.Logger
	router     http.Handler
	bufferPool *bpool.BufferPool
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.est",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the EST server handler.
func (h *Handler) Provision(ctx caddy.Context) error {

	h.processDefaults()

	h.logger = ctx.Logger(h)
	h.bufferPool = bpool.NewBufferPool(64)

	pkiModule, err := ctx.App("pki")
	if err != nil {
		return err
	}

	pkiApp := pkiModule.(*caddypki.PKI)

	pkiCA, ok := pkiApp.CAs[h.CA]
	if !ok {
		return fmt.Errorf("no certificate authority configured with id: %s", h.CA)
	}

	h.logger.Info(fmt.Sprintf("using ca: `%s (%s)` for issuing certificates over EST", pkiCA.Name, pkiCA.ID()))

	estLogger := logger.ZapWrappingLogger{
		Logger: h.logger,
	}

	estCA := ca.New(pkiCA, h.logger)

	basicAuthFunc := h.createBasicAuthFunc()

	estServerConfig := &est.ServerConfig{
		CA:             estCA,
		Logger:         estLogger,
		AllowedHosts:   h.AllowedHosts,
		Timeout:        time.Second * 30,
		RateLimit:      h.RateLimit,
		CheckBasicAuth: basicAuthFunc,
	}

	// Create a new globalsign/est router based on Chi
	r, err := est.NewRouter(estServerConfig)

	h.router = r

	return nil
}

// Validate sets up the EST server handler.
func (h *Handler) Validate() error {
	return nil
}

func (h *Handler) processDefaults() {

	if h.CA == "" {
		h.CA = "local"
	}

	if h.AllowedHosts == nil {
		h.AllowedHosts = []string{"localhost"}
	}

}

func (h *Handler) createBasicAuthFunc() func(ctx context.Context, r *http.Request, aps, username, password string) error {

	if h.EnableBasicAuth == nil || !*h.EnableBasicAuth {
		return nil
	}

	basicAuthFunc := func(ctx context.Context, r *http.Request, aps, username, password string) error {
		username, password, ok := r.BasicAuth()
		if !ok || username != h.BasicAuthUsername || password != h.BasicAuthPassword {
			return errors.New("http basic authentication required")
		}

		return nil
	}

	return basicAuthFunc
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	buffer := h.bufferPool.Get()
	defer h.bufferPool.Put(buffer)

	shouldBuffer := func(status int, header http.Header) bool {
		// TODO: add logic for performing buffering vs. not doing it
		// For now, we'll always buffer it
		return true
	}

	recorder := caddyhttp.NewResponseRecorder(w, buffer, shouldBuffer)

	h.router.ServeHTTP(recorder, r)

	if !recorder.Buffered() {
		// NOTE: not specifically required at this time, because we always buffer
	}

	// TODO: implement wrapping of errors written by the Chi router?

	recorder.Header().Set("server", serverHeader)

	// The body was not changed; write response the easy way
	return recorder.WriteResponse()
}

// Cleanup implements caddy.CleanerUpper and closes any idle databases.
func (h Handler) Cleanup() error {
	// TODO: do we have something to clean up?
	return nil
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
