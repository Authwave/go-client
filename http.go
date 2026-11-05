package authwave

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// SessionStore holds JSON-compatible records on the server. Implementations enforce expiry.
type SessionStore interface {
	Delete(context.Context, string) error
	Load(context.Context, string) (map[string]any, error)
	Save(context.Context, string, map[string]any, time.Time) error
}
type memoryEntry struct {
	data      []byte
	expiresAt time.Time
}

// MemorySessionStore is for development. Use shared persistent storage in production.
type MemorySessionStore struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{entries: make(map[string]memoryEntry)}
}
func (s *MemorySessionStore) Load(ctx context.Context, id string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[id]
	if !ok {
		return nil, nil
	}
	if !time.Now().Before(entry.expiresAt) {
		delete(s.entries, id)
		return nil, nil
	}
	var data map[string]any
	err := json.Unmarshal(entry.data, &data)
	return data, err
}
func (s *MemorySessionStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return nil
}
func (s *MemorySessionStore) Save(ctx context.Context, id string, data map[string]any, expiresAt time.Time) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[string]memoryEntry)
	}
	now := time.Now()
	for k, v := range s.entries {
		if !now.Before(v.expiresAt) {
			delete(s.entries, k)
		}
	}
	s.entries[id] = memoryEntry{data: encoded, expiresAt: expiresAt}
	return nil
}

type HTTPOptions struct {
	ClientKey       string
	AuthwaveHost    string
	OnAuthenticated func(*AuthUser) error
	Store           SessionStore
	CookieName      string
	// InsecureCookie permits local HTTP. Cookies are Secure by default.
	InsecureCookie bool
	TTL            time.Duration
}
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}
type HTTPHandler func(*Authenticator, *http.Request) (*Response, error)

var sessionIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var cookieNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// NewHTTPHandler buffers the result and persists sessions before writing any output.
func NewHTTPHandler(options HTTPOptions, handler HTTPHandler) (http.Handler, error) {
	if options.Store == nil {
		return nil, ErrSessionNotStarted
	}
	if options.CookieName == "" {
		options.CookieName = "authwave.sid"
	}
	if !cookieNamePattern.MatchString(options.CookieName) {
		return nil, fmt.Errorf("authwave: invalid cookie name")
	}
	if options.TTL == 0 {
		options.TTL = 24 * time.Hour
	}
	if options.TTL < time.Second {
		return nil, fmt.Errorf("authwave: TTL must be at least one second")
	}
	if handler == nil {
		return nil, fmt.Errorf("authwave: handler required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id := ""
		var data map[string]any
		var err error
		if cookie, e := r.Cookie(options.CookieName); e == nil && sessionIDPattern.MatchString(cookie.Value) {
			data, err = options.Store.Load(ctx, cookie.Value)
			if err != nil {
				http.Error(w, "Internal Server Error", 500)
				return
			}
			if data != nil {
				id = cookie.Value
			}
		}
		if data == nil {
			data = make(map[string]any)
			var bytes [32]byte
			if _, err = rand.Read(bytes[:]); err != nil {
				http.Error(w, "Internal Server Error", 500)
				return
			}
			id = hex.EncodeToString(bytes[:])
		}
		// Work on a detached record, even if a custom store returns a shared map.
		encoded, cloneErr := json.Marshal(data)
		if cloneErr != nil {
			http.Error(w, "Internal Server Error", 500)
			return
		}
		var detached map[string]any
		if cloneErr = json.Unmarshal(encoded, &detached); cloneErr != nil {
			http.Error(w, "Internal Server Error", 500)
			return
		}
		data = detached
		var previousIDs []string
		session, _ := NewGlobalSessionContainer(data, func() error {
			var bytes [32]byte
			if _, err := rand.Read(bytes[:]); err != nil {
				return err
			}
			previousIDs = append(previousIDs, id)
			id = hex.EncodeToString(bytes[:])
			return nil
		})
		// Persist even when application callbacks panic; let the HTTP server handle the panic.
		var response *Response
		func() {
			defer func() {
				for _, oldID := range previousIDs {
					if deleteErr := options.Store.Delete(context.WithoutCancel(ctx), oldID); deleteErr != nil {
						err = deleteErr
						return
					}
				}
				saveErr := options.Store.Save(context.WithoutCancel(ctx), id, data, time.Now().Add(options.TTL))
				if saveErr != nil {
					err = saveErr
				}
			}()
			var auth *Authenticator
			auth, err = NewAuthenticator(Options{ClientKey: options.ClientKey, CurrentURIPath: r.URL.RequestURI(), AuthwaveHost: options.AuthwaveHost, Session: session, OnAuthenticated: options.OnAuthenticated})
			if err == nil {
				response, err = handler(auth, r)
			}
		}()
		var redirect *RedirectError
		if err != nil && !errors.As(err, &redirect) {
			http.Error(w, "Internal Server Error", 500)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: options.CookieName, Value: id, Path: "/", HttpOnly: true, Secure: !options.InsecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: int(options.TTL / time.Second)})
		w.Header().Set("Cache-Control", "no-store")
		if redirect != nil {
			w.Header().Set("Location", redirect.URI)
			w.WriteHeader(redirect.Code)
			return
		}
		if response == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for k, values := range response.Header {
			if k == "Cache-Control" {
				continue
			}
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		status := response.Status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		_, _ = w.Write(response.Body)
	}), nil
}
