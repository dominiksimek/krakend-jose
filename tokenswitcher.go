package jose

import (
  "bytes"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "time"
)

type RawExtractorFactory func(string) func(r *http.Request) (string, error)

var ErrNotAuth = fmt.Errorf("not authorized")

type tokenBackendReq struct {
  AccountID int64  `json:"accountID"`
  AppID     int64  `json:"applicationID"`
  //Token     string `json:"token"`
}

type SignedTokensWrapper struct {
  Access  string `json:"access_token"`
  Refresh string `json:"refresh_token"`
}

// TokenSwitcher implements validation if user can access specific web application (endpoint) and appropriate
// switching of tokens.
type TokenSwitcher struct {
  cfg       *SignatureConfig
  extractor RawExtractorFactory
  httpExec  http.Client
}

// NewTokenSwitcher creates new TokenSwitcher object (constructor).
func NewTokenSwitcher(signatureConfig *SignatureConfig, ref RawExtractorFactory) *TokenSwitcher {
  ts := TokenSwitcher{cfg: signatureConfig, extractor: ref}
  ts.httpExec = http.Client{Timeout: 30 * time.Second}
  return &ts
}

// Validate validates if user can access specific endpoint according to its configuration and provided token (jwt).
// If user can't access endpoint with provided token, request for new token is generated (to backend).
func (self *TokenSwitcher) Validate(claims map[string]interface{}, req *http.Request) (*SignedTokensWrapper, error) {
  if self.cfg.WebAppIDKey == "" || self.cfg.WebExpAppID == 0 {
    return nil, nil
  }

  appID, err := ExtractInt64Claim(claims, self.cfg.WebAppIDKey)
  if err != nil {
    return nil, err
  }
  // validate provided app id vs expected app id
  if appID == self.cfg.WebExpAppID {
    // validation ok
    return nil, nil
  }

  // validation not ok, we need to switch token
  userID, err := ExtractInt64Claim(claims, self.cfg.WebUserIDKey)
  if err != nil {
    return nil, err
  }
  token, err := self.extractor(self.cfg.CookieKey)(req)
  if err != nil {
    return nil, err
  }
  newTokens, err := self.requestNewToken(userID, token)
  if err != nil {
    return nil, err
  }

  return newTokens, nil
}

func ExtractInt64Claim(claims map[string]interface{}, key string) (int64, error) {
  claim, ok := claims[key]
  if !ok {
    return 0, fmt.Errorf("tokenSwitcher.extractInt64Claim: key \"%s\" is not present in token", key)
  }
  claimFloat64, ok := claim.(float64)
  if !ok {
    return 0, fmt.Errorf("tokenSwitcher.extractInt64Claim: bad type of claim (%T)", claim)
  }
  return int64(claimFloat64), nil
}

// requestNewToken creates request for a new token and sends it to the configured backend.
func (self *TokenSwitcher) requestNewToken(userID int64, token string) (*SignedTokensWrapper, error) {
  tokenReq := tokenBackendReq{AccountID: userID, AppID: self.cfg.WebExpAppID}
  tokeReqBytes, err := json.Marshal(tokenReq)
  if err != nil {
    return nil, err
  }
  req, err := http.NewRequest(http.MethodPost, self.cfg.WebNewTokenUrl, bytes.NewBuffer(tokeReqBytes))
  if err != nil {
    return nil, err
  }
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("Authorization", "Bearer " + token)

  res, err := self.httpExec.Do(req)
  if err != nil {
    return nil, err
  }
  defer res.Body.Close()

  resBodyBytes, err := ioutil.ReadAll(res.Body)
  if err != nil {
    return nil, err
  }

  if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
    if res.StatusCode == http.StatusUnauthorized {
      return nil, ErrNotAuth
    }
    return nil, fmt.Errorf("invalid status code: %d", res.StatusCode)
  }

  var newTokens SignedTokensWrapper
  if err := json.Unmarshal(resBodyBytes, &newTokens); err != nil {
    return nil, err
  }

  return &newTokens, nil
}
