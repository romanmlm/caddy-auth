package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(UrlAuth{})
}

type UrlAuth struct {
	JWKeyEndpoint string `json:"jwkey_endpoint,omitempty"`
	logger        *zap.Logger
}

func (UrlAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.auth",
		New: func() caddy.Module { return new(UrlAuth) },
	}
}

func (ua *UrlAuth) Provision(ctx caddy.Context) error {
	ua.logger = ctx.Logger(ua)
	return nil
}

func (ua *UrlAuth) Validate() error {
	if ua.JWKeyEndpoint == "" {
		return fmt.Errorf("auth: jwkey_endpoint must be set to a valid JWKS endpoint of your IDP")
	}
	return nil
}

func (ua *UrlAuth) Authenticate(responseWriter http.ResponseWriter, request *http.Request) (caddyauth.User, bool, error) {
	responseWriter.WriteHeader(http.StatusUnauthorized)
	responseWriter.Header().Set("Content-Type", "application/json")
	resp := make(map[string]string)
	resp["message"] = "Unauthorized"
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		ua.logger.Error(err.Error())
		return caddyauth.User{}, false, err
	}
	responseWriter.Write(jsonResp)
	return caddyauth.User{}, false, nil
}

var (
	_ caddy.Provisioner       = (*UrlAuth)(nil)
	_ caddy.Validator         = (*UrlAuth)(nil)
	_ caddyauth.Authenticator = (*UrlAuth)(nil)
)
