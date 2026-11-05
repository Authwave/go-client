package authwave

import (
	"encoding/hex"
	"net/url"
	"strings"
)

const DefaultBaseRemoteURI = "login.authwave.com"
const QueryStringCipher = "c"
const QueryStringInitVector = "i"
const QueryStringCurrentURI = "u"
const QueryStringDeploymentID = "d"

func escape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "~", "%7E") }
func buildQuery(pairs ...string) string {
	parts := make([]string, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		parts = append(parts, escape(pairs[i])+"="+escape(pairs[i+1]))
	}
	return strings.Join(parts, "&")
}
func normalizeBaseURI(base string) (string, error) {
	if base == "" {
		base = DefaultBaseRemoteURI
	}
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", ErrInsecureProtocol
	}
	isTestHTTP := u.Scheme == "http" && strings.HasSuffix(strings.ToLower(strings.TrimRight(u.Hostname(), ".")), ".test")
	if u.Hostname() != "localhost" && u.Hostname() != "127.0.0.127" && !isTestHTTP && u.Scheme != "https" {
		return "", ErrInsecureProtocol
	}
	return u.Scheme + "://" + u.Host, nil
}
func providerURI(token *Token, currentPath, deploymentID, host, message string) (string, error) {
	base, err := normalizeBaseURI(host)
	if err != nil {
		return "", err
	}
	cipher, err := token.GenerateRequestCipher(message)
	if err != nil {
		return "", err
	}
	return base + "?" + buildQuery("c", cipher.String(), "d", deploymentID, "i", token.IV.String(), "u", hex.EncodeToString([]byte(currentPath))), nil
}
func NewLoginURI(token *Token, currentPath, deploymentID, host string) (string, error) {
	u, err := url.Parse(currentPath)
	if err != nil {
		return "", err
	}
	message := buildQuery("action", "login")
	if u.RawQuery != "" && u.RawQuery != "0" {
		message += "&" + buildQuery("returnQuery", u.RawQuery)
	}
	return providerURI(token, currentPath, deploymentID, host, message)
}
func NewLogoutURI(token *Token, currentPath, deploymentID, host string, redirectTo *string) (string, error) {
	message := buildQuery("action", "logout")
	if redirectTo != nil {
		message += "&" + buildQuery("redirectTo", *redirectTo)
	}
	return providerURI(token, currentPath, deploymentID, host, message)
}
func NewAdminURI(host string) (string, error) {
	base, err := normalizeBaseURI(host)
	if err != nil {
		return "", err
	}
	return base + "/admin/", nil
}
func withQuery(uri, query string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	u.RawQuery = strings.ReplaceAll(query, "#", "%23")
	u.ForceQuery = false
	return u.String(), nil
}
func withoutQueryValue(uri, key string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	var parts []string
	for _, part := range strings.Split(u.RawQuery, "&") {
		k := strings.SplitN(part, "=", 2)[0]
		decoded, _ := url.PathUnescape(k)
		if decoded != key {
			parts = append(parts, part)
		}
	}
	u.RawQuery = strings.Join(parts, "&")
	u.ForceQuery = false
	return u.String(), nil
}
