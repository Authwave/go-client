package authwave

import "encoding/json"

const SessionStoreKey = "Authwave\\SessionData"

// SessionData contains sensitive exchange data and belongs in server-side storage.
type SessionData struct {
	Token           *Token            `json:"token"`
	Data            *UserResponseData `json:"data"`
	ReturnQuery     *string           `json:"return_query"`
	CallbackInvoked bool              `json:"callback_invoked"`
}

func NewSessionData(token *Token, data *UserResponseData, returnQuery *string) *SessionData {
	return &SessionData{Token: token, Data: data, ReturnQuery: returnQuery}
}
func (d *SessionData) GetToken() (*Token, error) {
	if d.Token == nil {
		return nil, ErrNotLoggedIn
	}
	return d.Token, nil
}
func (d *SessionData) GetData() (*UserResponseData, error) {
	if d.Data == nil {
		return nil, ErrNotLoggedIn
	}
	return d.Data, nil
}
func (d *SessionData) GetReturnQuery() *string                { return d.ReturnQuery }
func (d *SessionData) HasInvokedAuthenticationCallback() bool { return d.CallbackInvoked }
func (d *SessionData) MarkAuthenticationCallbackInvoked()     { d.CallbackInvoked = true }

type SessionContainer interface {
	Get(string) (any, error)
	Set(string, any) error
	Contains(string) bool
	Remove(string) error
}
type GlobalSessionContainer struct{ data map[string]any }

func NewGlobalSessionContainer(data map[string]any) (*GlobalSessionContainer, error) {
	if data == nil {
		return nil, ErrSessionNotStarted
	}
	return &GlobalSessionContainer{data: data}, nil
}
func (s *GlobalSessionContainer) Get(key string) (any, error) {
	value := s.data[key]
	if key != SessionStoreKey || value == nil {
		return value, nil
	}
	if data, ok := value.(*SessionData); ok {
		return data, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var data SessionData
	if err = json.Unmarshal(encoded, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
func (s *GlobalSessionContainer) Set(key string, value any) error { s.data[key] = value; return nil }
func (s *GlobalSessionContainer) Contains(key string) bool        { _, ok := s.data[key]; return ok }
func (s *GlobalSessionContainer) Remove(key string) error         { delete(s.data, key); return nil }
