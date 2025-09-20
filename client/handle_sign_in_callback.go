package client

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/toaweme/log"

	"github.com/logto-io/go/v2/core"
)

func (logtoClient *LogtoClient) HandleSignInCallback(request *http.Request) error {
	log.Debug("logto", "call", "handle-sign-in-callback", "status", "starting")
	signInSession := SignInSession{}
	parseSignInSessionErr := json.Unmarshal([]byte(logtoClient.storage.GetItem(StorageKeySignInSession)), &signInSession)

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "parsed-sign-in-session", "error", parseSignInSessionErr)
	if parseSignInSessionErr != nil {
		return parseSignInSessionErr
	}

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "retrieving-code")
	callbackUri := GetOriginRequestUrl(request)
	code, retrieveCodeErr := core.VerifyAndParseCodeFromCallbackUri(callbackUri, signInSession.RedirectUri, signInSession.State)
	log.Debug("logto", "call", "handle-sign-in-callback", "status", "retrieved-code", "error", retrieveCodeErr)
	if retrieveCodeErr != nil {
		return retrieveCodeErr
	}
	log.Debug("logto", "call", "handle-sign-in-callback", "status", "fetching-oidc-config")

	oidcConfig, fetchOidcConfigErr := logtoClient.fetchOidcConfig()

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "fetched-oidc-config", "error", fetchOidcConfigErr)
	if fetchOidcConfigErr != nil {
		return fetchOidcConfigErr
	}

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "fetching-token")

	// this might be the problem
	codeTokenResponse, fetchTokenErr := core.FetchTokenByAuthorizationCode(logtoClient.httpClient, &core.FetchTokenByAuthorizationCodeOptions{
		TokenEndpoint: oidcConfig.TokenEndpoint,
		Code:          code,
		CodeVerifier:  signInSession.CodeVerifier,
		ClientId:      logtoClient.logtoConfig.AppId,
		ClientSecret:  logtoClient.logtoConfig.AppSecret,
		RedirectUri:   signInSession.RedirectUri,
	})

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "fetched-token", "error", fetchTokenErr, "token_response", codeTokenResponse)
	if fetchTokenErr != nil {
		return fetchTokenErr
	}

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "clearing-sign-in-session")

	logtoClient.storage.SetItem(StorageKeySignInSession, "")

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "cleared-sign-in-session")

	// - Save tokens to storage
	log.Debug("logto", "call", "handle-sign-in-callback", "status", "constructing-access-token")
	accessToken := AccessToken{
		Token:     codeTokenResponse.AccessToken,
		Scope:     codeTokenResponse.Scope,
		ExpiresAt: time.Now().Unix() + int64(codeTokenResponse.ExpireIn),
	}

	log.Debug("logto", "call", "handle-sign-in-callback", "status", "verifying-and-saving-token-response")

	// - Treat `scopes` as `empty` to construct the default access token key
	accessTokenKey := buildAccessTokenKey([]string{}, "", "")
	verificationErr := logtoClient.verifyAndSaveTokenResponse(
		codeTokenResponse.IdToken,
		codeTokenResponse.RefreshToken,
		accessTokenKey,
		accessToken,
		&oidcConfig,
	)
	log.Debug("logto", "call", "handle-sign-in-callback", "status", "verified-and-saved-token-response", "error", verificationErr)

	if verificationErr != nil {
		return verificationErr
	}

	return nil
}
