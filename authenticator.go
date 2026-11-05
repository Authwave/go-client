package authwave

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const SessionStoreKeyLegacy = "AUTHWAVE_CONSUMER_SESSION"
const ResponseQueryParameter = "AUTHWAVE_RESPONSE_DATA"
const FakeEmail = "fakelogin@authwave.com"

type Options struct {
	ClientKey       string
	CurrentURIPath  string
	AuthwaveHost    string
	Session         SessionContainer
	RedirectHandler RedirectHandler
	OnAuthenticated func(*AuthUser) error
}
type Authenticator struct {
	options              Options
	deploymentID, secret string
	sessionData          *SessionData
	user                 *AuthUser
	returnURI            *string
}

func NewAuthenticator(options Options) (*Authenticator, error) {
	if options.Session == nil {
		return nil, ErrSessionNotStarted
	}
	if options.AuthwaveHost == "" {
		options.AuthwaveHost = DefaultBaseRemoteURI
	}
	if options.RedirectHandler == nil {
		options.RedirectHandler = DefaultRedirectHandler
	}
	a := &Authenticator{options: options}
	split := strings.LastIndex(options.ClientKey, "_")
	if split >= 0 {
		a.deploymentID = options.ClientKey[:split]
		a.secret = options.ClientKey[split+1:]
	}
	value, err := options.Session.Get(SessionStoreKey)
	if err != nil {
		return nil, err
	}
	if value != nil {
		var ok bool
		a.sessionData, ok = value.(*SessionData)
		if !ok {
			return nil, fmt.Errorf("authwave: session container returned invalid data")
		}
		if a.sessionData.Data != nil {
			a.user = NewAuthUser(a.sessionData.Data.UserID, a.sessionData.Data.UserEmail)
		}
	}
	if err = a.completeAuth(); err != nil {
		return nil, err
	}
	return a, nil
}
func (a *Authenticator) SetReturnURI(uri string) { a.returnURI = &uri }
func (a *Authenticator) IsLoggedIn() bool        { return a.user != nil }
func (a *Authenticator) GetAuthUser() (*AuthUser, error) {
	if a.user == nil {
		return nil, ErrNotLoggedIn
	}
	return a.user, nil
}

// GetUser is deprecated. Use GetAuthUser.
func (a *Authenticator) GetUser() (*User, error) { return a.GetAuthUser() }
func (a *Authenticator) currentReturnURI() string {
	if a.returnURI != nil {
		return *a.returnURI
	}
	return a.options.CurrentURIPath
}
func (a *Authenticator) GetLoginURI(token *Token) (string, error) {
	return NewLoginURI(token, a.currentReturnURI(), a.deploymentID, a.options.AuthwaveHost)
}
func (a *Authenticator) GetAdminURI() (string, error) { return NewAdminURI(a.options.AuthwaveHost) }
func (a *Authenticator) Login(token *Token) error {
	if a.IsLoggedIn() {
		return nil
	}
	var err error
	if token == nil {
		token, err = NewToken(a.secret)
		if err != nil {
			return err
		}
	}
	u, err := url.Parse(a.currentReturnURI())
	if err != nil {
		return err
	}
	uri, err := a.GetLoginURI(token)
	if err != nil {
		return err
	}
	query := u.RawQuery
	a.sessionData = NewSessionData(token, nil, &query)
	if err = a.options.Session.Set(SessionStoreKey, a.sessionData); err != nil {
		return err
	}
	return a.options.RedirectHandler(uri, 303)
}
func (a *Authenticator) Logout(redirectTo *string, token *Token) error {
	fake := a.user != nil && a.user.Email() == FakeEmail
	if err := a.options.Session.Remove(SessionStoreKey); err != nil {
		return err
	}
	a.user = nil
	a.sessionData = nil
	if fake {
		return nil
	}
	var err error
	if token == nil {
		token, err = NewToken(a.secret)
		if err != nil {
			return err
		}
	}
	destination := redirectTo
	if destination == nil {
		destination = a.returnURI
	}
	if destination != nil && strings.HasPrefix(*destination, "?") {
		resolved, e := withQuery(a.options.CurrentURIPath, (*destination)[1:])
		if e != nil {
			return e
		}
		destination = &resolved
	}
	uri, err := NewLogoutURI(token, a.currentReturnURI(), a.deploymentID, a.options.AuthwaveHost, destination)
	if err != nil {
		return err
	}
	return a.options.RedirectHandler(uri, 303)
}
func (a *Authenticator) FakeLogin(userID string, email *string, redirectTo string) error {
	if redirectTo == "" {
		redirectTo = "/"
	}
	iv, err := NewInitVector()
	if err != nil {
		return err
	}
	requestIV, err := NewInitVector()
	if err != nil {
		return err
	}
	token := NewTokenWithIVs(a.secret, iv, requestIV)
	if err = a.options.Session.Set(SessionStoreKey, NewSessionData(token, nil, nil)); err != nil {
		return err
	}
	address := FakeEmail
	if email != nil {
		address = *email
	}
	data := NewUserResponseData(userID, address, nil)
	if err = a.options.Session.Set(SessionStoreKey, NewSessionData(token, data, nil)); err != nil {
		return err
	}
	plain, err := json.Marshal(map[string]string{"id": userID, "email": address})
	if err != nil {
		return err
	}
	cipher, err := Encrypt(string(plain), iv, a.secret)
	if err != nil {
		return err
	}
	return a.options.RedirectHandler(redirectTo+"?"+buildQuery(ResponseQueryParameter, cipher.String()), 303)
}
func scalar(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case json.Number:
		return string(v), nil
	case bool:
		if v {
			return "1", nil
		}
		return "", nil
	default:
		return "", ErrInvalidUserDataSerialization
	}
}
func (a *Authenticator) completeAuth() error {
	u, err := url.Parse(a.options.CurrentURIPath)
	if err != nil {
		return err
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return err
	}
	values := query[ResponseQueryParameter]
	if len(values) == 0 {
		return nil
	}
	cipher := strings.ReplaceAll(values[len(values)-1], " ", "+")
	if cipher == "" || cipher == "0" {
		return nil
	}
	if a.sessionData == nil {
		return a.tidyResponseData(nil)
	}
	token, err := a.sessionData.GetToken()
	if err != nil {
		return err
	}
	plain, err := Decrypt(cipher, token.SessionIV, a.secret)
	if err != nil {
		return err
	}
	var data map[string]any
	decoder := json.NewDecoder(strings.NewReader(plain))
	decoder.UseNumber()
	if !json.Valid([]byte(plain)) || decoder.Decode(&data) != nil || data == nil {
		return ErrInvalidUserDataSerialization
	}
	id, err := scalar(data["id"])
	if err != nil {
		return err
	}
	email, err := scalar(data["email"])
	if err != nil {
		return err
	}
	a.user = NewAuthUser(id, email)
	invoked := a.sessionData.CallbackInvoked
	next := NewSessionData(token, NewUserResponseData(id, email, nil), a.sessionData.ReturnQuery)
	if invoked || a.options.OnAuthenticated != nil {
		next.CallbackInvoked = true
	}
	if err = a.options.Session.Set(SessionStoreKey, next); err != nil {
		return err
	}
	if a.options.OnAuthenticated != nil && !invoked {
		if err = a.options.OnAuthenticated(a.user); err != nil {
			return err
		}
	}
	return a.tidyResponseData(next.ReturnQuery)
}
func (a *Authenticator) tidyResponseData(returnQuery *string) error {
	uri := a.options.CurrentURIPath
	var err error
	if returnQuery != nil {
		uri, err = withQuery(uri, *returnQuery)
		if err != nil {
			return err
		}
	}
	uri, err = withoutQueryValue(uri, ResponseQueryParameter)
	if err != nil {
		return err
	}
	return a.options.RedirectHandler(uri, 303)
}
