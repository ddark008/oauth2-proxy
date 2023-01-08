package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

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
	forceConfirm  string
	display       string
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
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = login
	s.PreferredUsername = login

	id, err := json.Get("id").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.User = id

	logger.Errorf("Session info %v", s)

	return nil
}

// TODO: Скопировать с google.go Redeem(), чтобы поддерживать пустой scope и refresh token, реализация по умолчанию в providers/provider_default.go

// ValidateSession validates the AccessToken
func (p *YandexProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeYandexHeader(s.AccessToken))
}

func makeYandexHeader(accessToken string) http.Header {
	return makeAuthorizationHeader("OAuth", accessToken, nil)
}

// GetLoginURL with typical oauth parameters
// codeChallenge and codeChallengeMethod are the PKCE challenge and method to append to the URL params.
// they will be empty strings if no code challenge should be presented
func (p *YandexProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	loginURL := makeYandexLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return loginURL.String()
}

func makeYandexLoginURL(p *ProviderData, redirectURI, state string, extraParams url.Values) url.URL {
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	if p.Scope != "" {
		params.Add("scope", p.Scope)
	}
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	for n, p := range extraParams {
		for _, v := range p {
			params.Add(n, v)
		}
	}
	a.RawQuery = params.Encode()
	return a
}
