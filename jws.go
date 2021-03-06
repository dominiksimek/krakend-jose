package jose

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/auth0-community/go-auth0"
	"github.com/devopsfaith/krakend/config"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	ValidatorNamespace = "github.com/devopsfaith/krakend-jose/validator"
	SignerNamespace    = "github.com/devopsfaith/krakend-jose/signer"
	defaultRolesKey    = "roles"
)

type SignatureConfig struct {
	Alg                      string   `json:"alg"`
	URI                      string   `json:"jwk-url"`
	CacheEnabled             bool     `json:"cache,omitempty"`
	CacheDuration            uint32   `json:"cache_duration,omitempty"`
	Issuer                   string   `json:"issuer,omitempty"`
	Audience                 []string `json:"audience,omitempty"`
	Roles                    []string `json:"roles,omitempty"`
	RolesKey                 string   `json:"roles_key,omitempty"`
	CookieKey                string   `json:"cookie_key,omitempty"`
	CipherSuites             []uint16 `json:"cipher_suites,omitempty"`
	DisableJWKSecurity       bool     `json:"disable_jwk_security"`
	Fingerprints             []string `json:"jwk_fingerprints,omitempty"`
	LocalCA                  string   `json:"jwk_local_ca,omitempty"`
	//
	WebAppIDKey              string   `json:"web_app_id_key,omitempty"`
	WebExpAppID              int64    `json:"web_expected_app_id,omitempty"`
	WebUserIDKey             string   `json:"web_user_id_key,omitempty"`
	WebNewTokenUrl           string   `json:"web_new_token_url,omitempty"`
	WebRedirectTo            string   `json:"web_redirect_to,omitempty"`
	WebReturnUrlBase         string   `json:"web_return_url_base,omitempty"`
	WebMaxAgeCookie          int      `json:"web_max_age_cookie,omitempty"`
	WebSecCookieDisable      bool     `json:"web_secure_cookie_disable,omitempty"`
	WebHttpOnlyCookieDisable bool     `json:"web_http_only_cookie_disable,omitempty"`
}

type SignerConfig struct {
	Alg                string   `json:"alg"`
	KeyID              string   `json:"kid"`
	URI                string   `json:"jwk-url"`
	FullSerialization  bool     `json:"full,omitempty"`
	KeysToSign         []string `json:"keys-to-sign,omitempty"`
	CipherSuites       []uint16 `json:"cipher_suites,omitempty"`
	DisableJWKSecurity bool     `json:"disable_jwk_security"`
	Fingerprints       []string `json:"jwk_fingerprints,omitempty"`
	LocalCA            string   `json:"jwk_local_ca,omitempty"`
}

var (
	ErrNoValidatorCfg = errors.New("JOSE: no validator config")
	ErrNoSignerCfg    = errors.New("JOSE: no signer config")
)

func GetSignatureConfig(cfg *config.EndpointConfig) (*SignatureConfig, error) {
	tmp, ok := cfg.ExtraConfig[ValidatorNamespace]
	if !ok {
		return nil, ErrNoValidatorCfg
	}
	data, _ := json.Marshal(tmp)
	res := new(SignatureConfig)
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}

	if res.RolesKey == "" {
		res.RolesKey = defaultRolesKey
	}
	if !strings.HasPrefix(res.URI, "https://") && !res.DisableJWKSecurity {
		return res, ErrInsecureJWKSource
	}
	return res, nil
}

func getSignerConfig(cfg *config.EndpointConfig) (*SignerConfig, error) {
	tmp, ok := cfg.ExtraConfig[SignerNamespace]
	if !ok {
		return nil, ErrNoSignerCfg
	}
	data, _ := json.Marshal(tmp)
	res := new(SignerConfig)
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(res.URI, "https://") && !res.DisableJWKSecurity {
		return res, ErrInsecureJWKSource
	}
	return res, nil
}

func NewSigner(cfg *config.EndpointConfig, te auth0.RequestTokenExtractor) (*SignerConfig, Signer, error) {
	signerCfg, err := getSignerConfig(cfg)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	decodedFs, err := DecodeFingerprints(signerCfg.Fingerprints)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	spcfg := SecretProviderConfig{
		URI:           signerCfg.URI,
		Cs:            signerCfg.CipherSuites,
		Fingerprints:  decodedFs,
		LocalCA:       signerCfg.LocalCA,
		AllowInsecure: signerCfg.DisableJWKSecurity,
	}

	sp, err := SecretProvider(spcfg, te)
	if err != nil {
		return signerCfg, nopSigner, err
	}
	key, err := sp.GetKey(signerCfg.KeyID)
	if err != nil {
		return signerCfg, nopSigner, err
	}
	if key.IsPublic() {
		// TODO: we should not sign with a public key
	}
	signingKey := jose.SigningKey{
		Key:       key.Key,
		Algorithm: jose.SignatureAlgorithm(signerCfg.Alg),
	}
	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): key.KeyID,
		},
	}
	s, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return signerCfg, nopSigner, err
	}

	if signerCfg.FullSerialization {
		return signerCfg, fullSerializeSigner{signer{s}}.Sign, nil
	}
	return signerCfg, compactSerializeSigner{signer{s}}.Sign, nil
}

type Signer func(interface{}) (string, error)

func nopSigner(_ interface{}) (string, error) { return "", nil }

type signer struct {
	signer jose.Signer
}

func (s signer) sign(v interface{}) (*jose.JSONWebSignature, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize payload: %s", err.Error())
	}
	return s.signer.Sign(data)
}

type fullSerializeSigner struct {
	signer
}

func (f fullSerializeSigner) Sign(v interface{}) (string, error) {
	obj, err := f.sign(v)
	if err != nil {
		return "", fmt.Errorf("unable to sign payload: %s", err.Error())
	}
	return obj.FullSerialize(), nil
}

type compactSerializeSigner struct {
	signer
}

func (c compactSerializeSigner) Sign(v interface{}) (string, error) {
	obj, err := c.sign(v)
	if err != nil {
		return "", fmt.Errorf("unable to sign payload: %s", err.Error())
	}
	return obj.CompactSerialize()
}
