package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/problem"

	"github.com/go-chi/chi/v5"
)

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := requestID(r)
		token := app.BearerToken(r.Header.Get("Authorization"))
		authenticator := s.cfg.Auth
		if token == "" && s.cfg.SessionAuth != nil {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				token = cookie.Value
				authenticator = s.cfg.SessionAuth
			}
		}
		if authenticator == nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		actor, err := authenticator.Authenticate(r.Context(), token)
		if err != nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

func (s *Server) requireProducerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := requestID(r)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && s.cfg.ProducerMTLSAuth.Lookup != nil {
			if len(r.TLS.VerifiedChains) == 0 {
				writeProblem(w, problem.Unauthorized(requestID))
				return
			}
			actor, err := s.cfg.ProducerMTLSAuth.AuthenticateCertificate(r.Context(), r.TLS.PeerCertificates[0])
			if err != nil {
				writeProblem(w, problem.Unauthorized(requestID))
				return
			}
			if !authz.Can(actor, "events:write", actor.TenantID) {
				writeProblem(w, problem.Forbidden(requestID))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
			return
		}
		token := app.BearerToken(r.Header.Get("Authorization"))
		if s.cfg.ProducerAuth != nil {
			actor, err := s.cfg.ProducerAuth.Authenticate(r.Context(), token)
			if err == nil {
				if !authz.Can(actor, "events:write", actor.TenantID) {
					writeProblem(w, problem.Forbidden(requestID))
					return
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
				return
			}
			if !errors.Is(err, app.ErrUnauthorized) {
				writeProblem(w, problem.Internal(requestID))
				return
			}
		}
		if s.cfg.Auth == nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		actor, err := s.cfg.Auth.Authenticate(r.Context(), token)
		if err != nil {
			writeProblem(w, problem.Unauthorized(requestID))
			return
		}
		if !authz.Can(actor, "events:write", actor.TenantID) {
			writeProblem(w, problem.Forbidden(requestID))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

func (s *Server) requireSCIMAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Control == nil {
			writeProblem(w, problem.Unauthorized(requestID(r)))
			return
		}
		actor, err := s.cfg.Control.AuthenticateSCIMToken(r.Context(), app.BearerToken(r.Header.Get("Authorization")))
		if err != nil {
			writeProblem(w, problem.Unauthorized(requestID(r)))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor)))
	})
}

func (s *Server) issueOAuthToken(w http.ResponseWriter, r *http.Request) {
	body, ok := readLimitedBody(w, r, 64<<10)
	if !ok {
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeProblem(w, problem.BadRequest(requestID(r), "validation_error", "Invalid form body."))
		return
	}
	if form.Get("grant_type") != "client_credentials" {
		writeProblem(w, problem.BadRequest(requestID(r), "unsupported_grant_type", "Only client_credentials grant is supported."))
		return
	}
	if form.Get("client_secret") != "" {
		writeProblem(w, problem.BadRequest(requestID(r), "invalid_request", "Client credentials must use HTTP Basic authentication."))
		return
	}
	clientID, clientSecret, basicOK := r.BasicAuth()
	if !basicOK || strings.TrimSpace(clientID) == "" || clientSecret == "" {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	result, err := s.cfg.Control.IssueProducerToken(r.Context(), clientID, clientSecret)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	result, err := s.cfg.Control.BeginOIDCLogin(r.Context(), r.URL.Query().Get("tenant_id"), r.URL.Query().Get("provider_id"), r.URL.Query().Get("redirect_after"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setCookie(w, &http.Cookie{Name: "webhookery_oidc_state", Value: result.State, Path: "/v1/auth/oidc", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, result.AuthURL, http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("webhookery_oidc_state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	result, err := s.cfg.Control.CompleteOIDCCallback(r.Context(), state, r.URL.Query().Get("code"), r.UserAgent(), s.remoteAddr(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setCookie(w, &http.Cookie{Name: sessionCookieName, Value: result.SessionToken, Path: "/", Expires: result.Session.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	s.setCookie(w, &http.Cookie{Name: "webhookery_oidc_state", Value: "", Path: "/v1/auth/oidc", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"session": result.Session, "actor": result.Actor})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	if err := s.cfg.Control.LogoutSession(r.Context(), actorFrom(r), cookie.Value); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeProblem(w, problem.Unauthorized(requestID(r)))
		return
	}
	item, err := s.cfg.Control.CurrentAuthSession(r.Context(), actorFrom(r), cookie.Value)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listAuthSessions(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAuthSessions(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) revokeAuthSession(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RevokeAuthSessionByID(r.Context(), actorFrom(r), chi.URLParam(r, "session_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) setCookie(w http.ResponseWriter, cookie *http.Cookie) {
	cookie.Secure = true
	cookie.HttpOnly = true
	if cookie.SameSite == http.SameSiteDefaultMode {
		cookie.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, cookie)
}

func (s *Server) createIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.CreateIdentityProviderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateIdentityProvider(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listIdentityProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListIdentityProviders(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) getIdentityProvider(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.GetIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateIdentityProviderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) testIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.TestIdentityProvider(r.Context(), actorFrom(r), chi.URLParam(r, "provider_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createSCIMToken(w http.ResponseWriter, r *http.Request) {
	var req app.CreateSCIMTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateSCIMToken(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listSCIMTokens(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListSCIMTokens(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) revokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.RevokeSCIMToken(r.Context(), actorFrom(r), chi.URLParam(r, "token_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.SCIMListUsers(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scimListResponse(items))
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMCreateUser(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMGetUser(r.Context(), actorFrom(r), chi.URLParam(r, "user_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ID = chi.URLParam(r, "user_id")
	item, err := s.cfg.Control.SCIMReplaceUser(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMPatchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMPatchUser(r.Context(), actorFrom(r), chi.URLParam(r, "user_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMDeactivateUser(r.Context(), actorFrom(r), chi.URLParam(r, "user_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.SCIMListGroups(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scimListResponse(items))
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMCreateGroup(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMGetGroup(r.Context(), actorFrom(r), chi.URLParam(r, "group_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ID = chi.URLParam(r, "group_id")
	item, err := s.cfg.Control.SCIMReplaceGroup(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	var req app.SCIMPatchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.SCIMPatchGroup(r.Context(), actorFrom(r), chi.URLParam(r, "group_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	item, err := s.cfg.Control.SCIMDeactivateGroup(r.Context(), actorFrom(r), chi.URLParam(r, "group_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req app.CreateRoleBindingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateRoleBinding(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListRoleBindings(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) updateRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateRoleBindingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateRoleBinding(r.Context(), actorFrom(r), chi.URLParam(r, "binding_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableRoleBinding(r.Context(), actorFrom(r), chi.URLParam(r, "binding_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createAccessPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req app.CreateAccessPolicyRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.CreateAccessPolicyRule(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAccessPolicyRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.cfg.Control.ListAccessPolicyRules(r.Context(), actorFrom(r), queryLimit(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(items))
}

func (s *Server) updateAccessPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req app.UpdateAccessPolicyRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.UpdateAccessPolicyRule(r.Context(), actorFrom(r), chi.URLParam(r, "policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) disableAccessPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req app.StateChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.DisableAccessPolicyRule(r.Context(), actorFrom(r), chi.URLParam(r, "policy_id"), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) authzExplain(w http.ResponseWriter, r *http.Request) {
	var req app.AuthzExplainRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := s.cfg.Control.ExplainAuthorization(r.Context(), actorFrom(r), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
