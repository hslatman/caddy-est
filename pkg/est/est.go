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
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"go.uber.org/zap"

	"github.com/globalsign/est"

	"github.com/hslatman/caddy-est/internal/ca"
	"github.com/hslatman/caddy-est/internal/logger"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is an EST server handler
type Handler struct {
	CA   string `json:"ca,omitempty"`
	Host string `json:"host,omitempty"`
	//PathPrefix string `json:"path_prefix,omitempty"`

	logger  *zap.Logger
	handler http.Handler

	// privKey *rsa.PrivateKey
	// cert    *x509.Certificate
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.est",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the ACME server handler.
func (h *Handler) Provision(ctx caddy.Context) error {

	h.processDefaults()

	h.logger = ctx.Logger(h)

	pkiModule, err := ctx.App("pki")
	if err != nil {
		return err
	}

	pkiApp := pkiModule.(*caddypki.PKI)
	fmt.Println(pkiApp)
	fmt.Println(fmt.Sprintf("%#+v", pkiApp.CAs))
	pkiCA, ok := pkiApp.CAs[h.CA]
	if !ok {
		return fmt.Errorf("no certificate authority configured with id: %s", h.CA)
	}

	fmt.Println(pkiCA)

	logger := logger.New(os.Stderr)

	estCA := ca.New(pkiCA)

	// Create server mux.
	r, err := est.NewRouter(&est.ServerConfig{
		CA:             estCA,
		Logger:         logger,          //logger,
		AllowedHosts:   nil,             //cfg.AllowedHosts,
		Timeout:        time.Second * 0, // time.Duration(cfg.Timeout) * time.Second,
		RateLimit:      0,               //cfg.RateLimit,
		CheckBasicAuth: nil,             //pwfunc,
	})

	fmt.Println(r)

	h.handler = r

	// logger := log.NewJSONLogger(os.Stderr)
	// debug := level.Debug(logger)

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

	// TODO: record the response, overwrite pieces? Like a header.
	// Of course that could be done using a header directive too, but it would be nice
	// to specify something different than the default `"GlobalSign EST Server v1.0.3`
	// from the embedded Chi router.
	// TODO: implement wrapper for errors written by the Chi router?

	fmt.Println(fmt.Sprintf("%#+v", r))

	h.handler.ServeHTTP(w, r)

	return nil

	// if strings.HasPrefix(r.URL.Path, h.PathPrefix) {
	// 	fmt.Println("serving scep endpoint")

	// 	fmt.Println(fmt.Sprintf("%#+v", r))

	// 	h.handler.ServeHTTP(w, r)

	// 	fmt.Println("done")

	// 	return nil
	// }

	//return next.ServeHTTP(w, r)
}

// Cleanup implements caddy.CleanerUpper and closes any idle databases.
func (h Handler) Cleanup() error {
	// key := ash.getDatabaseKey()
	// deleted, err := databasePool.Delete(key)
	// if deleted {
	// 	ash.logger.Debug("unloading unused CA database", zap.String("db_key", key))
	// }
	// if err != nil {
	// 	ash.logger.Error("closing CA database", zap.String("db_key", key), zap.Error(err))
	// }
	// return err
	return nil
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
