package main

import (
	"encoding/json"
	authwave "github.com/Authwave/go-client"
	"log"
	"net/http"
	"os"
)

func main() {
	key := os.Getenv("AUTHWAVE_CLIENT_KEY")
	if key == "" {
		log.Fatal("Set AUTHWAVE_CLIENT_KEY")
	}
	handler, err := authwave.NewHTTPHandler(authwave.HTTPOptions{
		ClientKey: key, Store: authwave.NewMemorySessionStore(), InsecureCookie: true, // Local HTTP only.
	}, func(auth *authwave.Authenticator, r *http.Request) (*authwave.Response, error) {
		switch r.URL.Path {
		case "/login":
			auth.SetReturnURI("/")
			if err := auth.Login(nil); err != nil {
				return nil, err
			}
		case "/logout":
			destination := "/"
			if err := auth.Logout(&destination, nil); err != nil {
				return nil, err
			}
		}
		result := map[string]string{"login": "/login"}
		if auth.IsLoggedIn() {
			user, err := auth.GetAuthUser()
			if err != nil {
				return nil, err
			}
			result = map[string]string{"id": user.ID(), "email": user.Email()}
		}
		body, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		return &authwave.Response{Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe("127.0.0.1:3000", handler))
}
