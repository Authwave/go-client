package authwave

import "encoding/json"

type Token struct {
	Secret    string     `json:"secret"`
	SessionIV InitVector `json:"session_iv"`
	IV        InitVector `json:"iv"`
}

// NewToken generates both nonces. Use NewTokenWithIVs for deterministic exchange tests.
func NewToken(secret string) (*Token, error) {
	sessionIV, err := NewInitVector()
	if err != nil {
		return nil, err
	}
	iv, err := NewInitVector()
	if err != nil {
		return nil, err
	}
	return NewTokenWithIVs(secret, sessionIV, iv), nil
}
func NewTokenWithIVs(secret string, sessionIV, iv InitVector) *Token {
	return &Token{Secret: secret, SessionIV: sessionIV, IV: iv}
}
func (t *Token) GetIV() InitVector       { return t.IV }
func (t *Token) GetSecretIV() InitVector { return t.SessionIV }
func (t *Token) GenerateRequestCipher(message string) (CipherText, error) {
	return Encrypt(message+"&secretIv="+t.SessionIV.String(), t.IV, t.Secret)
}
func (t *Token) Decode(cipher string) (*UserResponseData, error) {
	plain, err := Decrypt(cipher, t.IV, t.Secret)
	if err != nil {
		return nil, err
	}
	var data map[string]json.RawMessage
	if json.Unmarshal([]byte(plain), &data) != nil || data == nil {
		return nil, ErrInvalidUserDataSerialization
	}
	idValue := data["uuid"]
	if len(idValue) == 0 || string(idValue) == "null" {
		idValue = data["id"]
	}
	var id, email string
	if len(idValue) == 0 || string(idValue) == "null" || json.Unmarshal(idValue, &id) != nil || len(data["email"]) == 0 || string(data["email"]) == "null" || json.Unmarshal(data["email"], &email) != nil {
		return nil, ErrInvalidUserDataSerialization
	}
	return NewUserResponseData(id, email, nil), nil
}
