package gin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	krakendjose "github.com/devopsfaith/krakend-jose"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	ginkrakend "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return TokenSigner(TokenSignatureValidator(hf, logger, rejecterF), logger)
}

func TokenSigner(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Info("JOSE: singer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error(err.Error(), cfg.Endpoint)
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: singer enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			proxyReq := ginkrakend.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
			ctx, cancel := context.WithTimeout(c, cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error("proxy response error:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if response == nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := krakendjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				c.Header(k, v[0])
			}
			c.JSON(response.Metadata.StatusCode, response.Data)
		}
	}
}

func TokenSignatureValidator(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		validator, err := krakendjose.NewValidator(scfg, FromCookie)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		var aclCheck func(string, map[string]interface{}, []string) bool

		if strings.Contains(scfg.RolesKey, ".") {
			aclCheck = krakendjose.CanAccessNested
		} else {
			aclCheck = krakendjose.CanAccess
		}

		tokenSwitcher := krakendjose.NewTokenSwitcher(scfg, FromHeaderAndCookieRaw)

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			token, err := validator.ValidateRequest(c.Request)
			if err != nil {
				if scfg.WebRedirectTo != "" {
					logger.Error("JOSE: redirecting to", scfg.WebRedirectTo, "(validate request:", err, ")")
					c.Redirect(http.StatusFound, scfg.WebRedirectTo)
					c.Abort()
				} else {
					c.AbortWithError(http.StatusUnauthorized, err)
				}
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(c.Request, token, &claims)
			if err != nil {
				if scfg.WebRedirectTo != "" {
					logger.Error("JOSE: redirecting to", scfg.WebRedirectTo, "(parsing claims:", err, ")")
					c.Redirect(http.StatusFound, scfg.WebRedirectTo)
					c.Abort()
				} else {
					c.AbortWithError(http.StatusUnauthorized, err)
				}
				return
			}

			if rejecter.Reject(claims) {
				if scfg.WebRedirectTo != "" {
					logger.Debug("JOSE: redirecting to", scfg.WebRedirectTo, "(reject)")
					c.Redirect(http.StatusFound, scfg.WebRedirectTo)
					c.Abort()
				} else {
					c.AbortWithStatus(http.StatusUnauthorized)
				}
				return
			}

			if !aclCheck(scfg.RolesKey, claims, scfg.Roles) {
				if scfg.WebRedirectTo != "" {
					logger.Debug("JOSE: redirecting to", scfg.WebRedirectTo, "(acl check)")
					c.Redirect(http.StatusFound, scfg.WebRedirectTo)
					c.Abort()
				} else {
					c.AbortWithStatus(http.StatusForbidden)
				}
				return
			}

			// check if user can access web app/endpoint (if configured)
			newTokens, err := tokenSwitcher.Validate(claims, c.Request)
			if err != nil {
				if scfg.WebRedirectTo != "" {
					logger.Debug("JOSE: redirecting to", scfg.WebRedirectTo, "(switch token)")
					c.Redirect(http.StatusFound, scfg.WebRedirectTo)
					c.Abort()
				} else {
					c.AbortWithError(http.StatusForbidden, err)
				}
				return
			}

			// set cookie if new token was issued
			if newTokens != nil {
				maxAge := 60 * 60 * 24 * 7
				c.SetCookie(scfg.CookieKey, newTokens.Access, maxAge, "/","", !scfg.WebSecCookieDisable, false)
			}

			handler(c)
		}
	}
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}

func FromHeaderAndCookieRaw(key string) func(r *http.Request) (string, error) {
  if key == "" {
    key = "access_token"
  }
  return func(r *http.Request) (string, error) {
    raw := ""
    if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[0:7], "BEARER ") {
      raw = h[7:]
    }
    if raw != "" {
      return raw, nil
    }
    //
    cookie, err := r.Cookie(key)
    if err != nil {
      return "", auth0.ErrTokenNotFound
    }
    return cookie.Value, nil
  }
}

func calcCookieMaxAge(claims map[string]interface{}) (int64, error) {
  iat, err := krakendjose.ExtractInt64Claim(claims, "iat")
  if err != nil {
    return 0, err
  }
  exp, err := krakendjose.ExtractInt64Claim(claims, "exp")
  if err != nil {
    return 0, err
  }
  return exp - iat, nil
}
