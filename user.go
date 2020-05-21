package authwave

// AuthUser is an immutable identity snapshot. An email can change; use ID for local records.
type AuthUser struct {
	id    string
	email string
}

func NewAuthUser(id, email string) *AuthUser { return &AuthUser{id: id, email: email} }
func (u *AuthUser) ID() string               { return u.id }
func (u *AuthUser) Email() string            { return u.email }

// User is the deprecated compatibility name. Use AuthUser.
type User = AuthUser

type BaseResponseData struct {
	Message *string `json:"message"`
}

func (d *BaseResponseData) GetMessage() *string { return d.Message }

type UserResponseData struct {
	BaseResponseData
	UserID    string `json:"id"`
	UserEmail string `json:"email"`
}

func NewUserResponseData(id, email string, message *string) *UserResponseData {
	return &UserResponseData{BaseResponseData: BaseResponseData{Message: message}, UserID: id, UserEmail: email}
}
func (d *UserResponseData) GetID() string    { return d.UserID }
func (d *UserResponseData) GetEmail() string { return d.UserEmail }
