package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type YandexProvider struct {
	*ProviderData
	deviceId      string
	deviceName    string
	loginHint     string
	optionalScope string
	forceConfirm  bool
}

var _ Provider = (*YandexProvider)(nil)

const (
	yandexProviderName = "Yandex"
	yandexDefaultScope = ""
)

var (
	// Default Login URL for Yandex.
	// Pre-parsed URL of https://oauth.yandex.ru/authorize.
	yandexDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "oauth.yandex.ru",
		Path:   "/authorize",
	}

	// Default Redeem URL for Yandex.
	// Pre-parsed URL of https://oauth.yandex.ru/token.
	yandexDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "oauth.yandex.ru",
		Path:   "/token",
	}

	// Default Validation URL for Yandex.
	// Pre-parsed URL of https://login.yandex.ru/info?format=json.
	yandexDefaultValidateURL = &url.URL{
		Scheme:   "https",
		Host:     "login.yandex.ru",
		Path:     "/info",
		RawQuery: "format=json",
	}

	// Default Profile URL for Yandex.
	// Pre-parsed URL of https://login.yandex.ru/info?format=json.
	yandexDefaultProfileURL = &url.URL{
		Scheme:   "https",
		Host:     "login.yandex.ru",
		Path:     "/info",
		RawQuery: "format=json",
	}
)

// NewYandexProvider creates a YandexProvider using the passed ProviderData
func NewYandexProvider(p *ProviderData, opts options.YandexOptions) (*YandexProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name:        yandexProviderName,
		loginURL:    yandexDefaultLoginURL,
		redeemURL:   yandexDefaultRedeemURL,
		profileURL:  yandexDefaultProfileURL,
		validateURL: yandexDefaultValidateURL,
		scope:       yandexDefaultScope,
	})

	provider := &YandexProvider{ProviderData: p}

	if err := provider.configure(opts); err != nil {
		return nil, fmt.Errorf("could not configure yandex provider: %v", err)
	}

	return provider, nil
}

func (p *YandexProvider) configure(opts options.YandexOptions) error {
	match, _ := regexp.MatchString("[ -~]{6,50}", opts.DeviceId)
	if opts.DeviceId != "" && !match {
		return fmt.Errorf("option Device ID must contains only ANSII (32-128 code) with length between 6 and 50: %v", opts.DeviceId)
	}
	p.deviceId = opts.DeviceId
	if len(opts.DeviceName) > 100 {
		return fmt.Errorf("length of Device Name must be less 100: %v", opts.DeviceName)
	}
	p.deviceName = opts.DeviceName
	p.loginHint = opts.LoginHint
	p.optionalScope = opts.OptionalScope
	p.forceConfirm = opts.ForceConfirm
	return nil
}

// EnrichSession uses the Yandex userinfo endpoint to populate the session's
// id and login.
func (p *YandexProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		WithHeaders(makeYandexHeader(s.AccessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	login, err := json.Get("login").String()
	if err != nil {
		return fmt.Errorf("unable to extract login from userinfo endpoint: %v", err)
	}
	s.Email = login
	s.PreferredUsername = login

	id, err := json.Get("id").String()
	if err != nil {
		return fmt.Errorf("unable to extract id from userinfo endpoint: %v", err)
	}
	s.User = id

	email, err := json.Get("default_email").String()
	if err != nil {
		logger.Printf("unable to get email from userinfo endpoint: %v", err)
	} else {
		s.Email = email
	}
	return nil
}

// ValidateSession validates the AccessToken
func (p *YandexProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeYandexHeader(s.AccessToken))
}

func makeYandexHeader(accessToken string) http.Header {
	return makeAuthorizationHeader("OAuth", accessToken, nil)
}

// GetLoginURL with additional yandex parametes
func (p *YandexProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	if p.deviceId != "" {
		extraParams.Add("device_id", p.deviceId)
	}
	if p.deviceName != "" {
		extraParams.Add("device_name", p.deviceName)
	}
	if p.loginHint != "" {
		extraParams.Add("login_hint", p.loginHint)
	}
	if p.optionalScope != "" {
		extraParams.Add("optional_scope", p.optionalScope)
	}
	if p.forceConfirm {
		extraParams.Add("force_confirm", "yes")
	}
	loginURL := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	if p.Scope == "" {
		q := loginURL.Query()
		q.Del("scope")
		loginURL.RawQuery = q.Encode()
	}
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authorization code for an access token
func (p *YandexProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,
	}
	session.CreatedAtNow()
	session.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return session, nil
}

// RefreshSession uses the RefreshToken to fetch new Access Token
func (p *YandexProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (p *YandexProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("grant_type", "refresh_token")
	params.Add("refresh_token", s.RefreshToken)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	s.AccessToken = jsonResponse.AccessToken
	s.RefreshToken = jsonResponse.RefreshToken

	s.CreatedAtNow()
	s.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return nil
}
