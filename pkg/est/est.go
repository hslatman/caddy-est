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
	CA   string `json:"ca,omitempty"`
	Host string `json:"host,omitempty"`

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

	logger := logger.ZapWrappingLogger{
		Logger: h.logger,
	}

	estCA := ca.New(pkiCA, h.logger)

	estServerConfig := &est.ServerConfig{
		CA:             estCA,
		Logger:         logger,
		AllowedHosts:   nil,             //cfg.AllowedHosts,
		Timeout:        time.Second * 0, // time.Duration(cfg.Timeout) * time.Second,
		RateLimit:      0,               //cfg.RateLimit,
		CheckBasicAuth: nil,             //pwfunc,
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

	if h.Host == "" {
		h.Host = "localhost"
	}

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

	// TODO: handle the case that the response is empty (i.e. 404, 204, etc)?

	if !recorder.Buffered() {
		// NOTE: not specifically required at this time
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
