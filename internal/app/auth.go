package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"webhookery/internal/authz"
)

type Authenticator interface {
	Authenticate(ctx context.Context, bearerToken string) (authz.Actor, error)
}

type APIKeyLookup interface {
	AuthenticateAPIKey(ctx context.Context, keyHash string) (authz.Actor, error)
}

type APIKeyAuthenticator struct {
	Lookup APIKeyLookup
}

func (a APIKeyAuthenticator) Authenticate(ctx context.Context, bearerToken string) (authz.Actor, error) {
	if bearerToken == "" || a.Lookup == nil {
		return authz.Actor{}, ErrUnauthorized
	}
	return a.Lookup.AuthenticateAPIKey(ctx, HashToken(bearerToken))
}

type MultiAuthenticator struct {
	Authenticators []Authenticator
}

func (m MultiAuthenticator) Authenticate(ctx context.Context, bearerToken string) (authz.Actor, error) {
	for _, authn := range m.Authenticators {
		if authn == nil {
			continue
		}
		actor, err := authn.Authenticate(ctx, bearerToken)
		if err == nil {
			return actor, nil
		}
		if !errors.Is(err, ErrUnauthorized) {
			return authz.Actor{}, err
		}
	}
	return authz.Actor{}, ErrUnauthorized
}

type StaticAuthenticator struct {
	Hash  string
	Actor authz.Actor
}

func NewStaticAuthenticator(rawToken string, actor authz.Actor) StaticAuthenticator {
	return StaticAuthenticator{Hash: HashToken(rawToken), Actor: actor}
}

func (a StaticAuthenticator) Authenticate(ctx context.Context, bearerToken string) (authz.Actor, error) {
	_ = ctx
	if bearerToken == "" || a.Hash == "" {
		return authz.Actor{}, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(HashToken(bearerToken)), []byte(a.Hash)) != 1 {
		return authz.Actor{}, ErrUnauthorized
	}
	return a.Actor, nil
}

func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func BearerToken(header string) string {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
