package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-martini/martini"
	gooauth2 "github.com/golang/oauth2"
	"github.com/martini-contrib/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type Authenticator interface {
	Authenticate([]string, martini.Context, oauth2.Tokens, http.ResponseWriter, *http.Request)
	Handler() martini.Handler
}

func NewAuthenticator(conf *Conf) Authenticator {
	var authenticator Authenticator

	if conf.Auth.Info.Service == "google" {
		handler := oauth2.Google(&gooauth2.Options{
			ClientID:     conf.Auth.Info.ClientId,
			ClientSecret: conf.Auth.Info.ClientSecret,
			RedirectURL:  conf.Auth.Info.RedirectURL,
			Scopes:       []string{"email"},
		})
		authenticator = &GoogleAuth{&BaseAuth{handler, conf}}
	} else if conf.Auth.Info.Service == "github" {
		handler := GithubGeneral(&gooauth2.Options{
			ClientID:     conf.Auth.Info.ClientId,
			ClientSecret: conf.Auth.Info.ClientSecret,
			RedirectURL:  conf.Auth.Info.RedirectURL,
			Scopes:       []string{"read:org"},
		}, conf)
		authenticator = &GitHubAuth{&BaseAuth{handler, conf}}
	} else {
		panic("unsupported authentication method")
	}

	return authenticator
}

// Currently, martini-contrib/oauth2 doesn't support github enterprise directly.
func GithubGeneral(opts *gooauth2.Options, conf *Conf) martini.Handler {
	authUrl := fmt.Sprintf("%s/login/oauth/authorize", conf.Auth.Info.Endpoint)
	tokenUrl := fmt.Sprintf("%s/login/oauth/access_token", conf.Auth.Info.Endpoint)

	return oauth2.NewOAuth2Provider(opts, authUrl, tokenUrl)
}

type BaseAuth struct {
	handler martini.Handler
	conf    *Conf
}

func (b *BaseAuth) Handler() martini.Handler {
	return b.handler
}

type GoogleAuth struct {
	*BaseAuth
}

func (a *GoogleAuth) Authenticate(domain []string, c martini.Context, tokens oauth2.Tokens, w http.ResponseWriter, r *http.Request) {
	extra := tokens.ExtraData()
	if _, ok := extra["id_token"]; ok == false {
		log.Printf("id_token not found")
		forbidden(w)
		return
	}

	keys := strings.Split(extra["id_token"], ".")
	if len(keys) < 2 {
		log.Printf("invalid id_token")
		forbidden(w)
		return
	}

	data, err := base64Decode(keys[1])
	if err != nil {
		log.Printf("failed to decode base64: %s", err.Error())
		forbidden(w)
		return
	}

	var info map[string]interface{}
	if err := json.Unmarshal(data, &info); err != nil {
		log.Printf("failed to decode json: %s", err.Error())
		forbidden(w)
		return
	}

	if email, ok := info["email"].(string); ok {
		var user *User
		if len(domain) > 0 {
			for _, d := range domain {
				if strings.Contains(d, "@") {
					if d == email {
						user = &User{email}
					}
				} else {
					if strings.HasSuffix(email, "@"+d) {
						user = &User{email}
						break
					}
				}
			}
		} else {
			user = &User{email}
		}

		if user != nil {
			log.Printf("user %s logged in", email)
			c.Map(user)
		} else {
			log.Printf("email doesn't allow: %s", email)
			forbidden(w)
			return
		}
	} else {
		log.Printf("email not found")
		forbidden(w)
		return
	}
}

type GitHubAuth struct {
	*BaseAuth
}

type OrgTeam struct {
	organization string
	team string
}

func (a *GitHubAuth) Authenticate(organizations []string, c martini.Context, tokens oauth2.Tokens, w http.ResponseWriter, r *http.Request) {
	if len(organizations) > 0 {
		var orgSlice []OrgTeam
		var teamSlice []OrgTeam
		for _, org := range organizations {
			var orgArray = strings.Split(org, "/")
			if len(orgArray) > 1 {
				teamSlice = append(teamSlice, OrgTeam{organization: orgArray[0], team: orgArray[1]})
			} else {
				orgSlice = append(orgSlice, OrgTeam{organization: orgArray[0]})
			}
		}

		if len(orgSlice) > 0 {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/user/orgs", a.conf.Auth.Info.ApiEndpoint), nil)
			if err != nil {
				log.Printf("failed to create a request to retrieve organizations: %s", err)
				forbidden(w)
				return
			}

			req.SetBasicAuth(tokens.Access(), "x-oauth-basic")

			client := http.Client{}
			res, err := client.Do(req)
			if err != nil {
				log.Printf("failed to retrieve organizations: %s", err)
				forbidden(w)
				return
			}

			data, err := ioutil.ReadAll(res.Body)
			res.Body.Close()

			if err != nil {
				log.Printf("failed to read body of GitHub response: %s", err)
				forbidden(w)
				return
			}

			var info []map[string]interface{}
			if err := json.Unmarshal(data, &info); err != nil {
				log.Printf("failed to decode json: %s", err.Error())
				forbidden(w)
				return
			}

			for _, userOrg := range info {
				for _, org := range orgSlice {
					if userOrg["login"] == org.organization {
						return
					}
				}
			}
		}
		if len(teamSlice) > 0 {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/user/teams", a.conf.Auth.Info.ApiEndpoint), nil)
			if err != nil {
				log.Printf("failed to create a request to retrieve teams: %s", err)
				forbidden(w)
				return
			}

			req.SetBasicAuth(tokens.Access(), "x-oauth-basic")

			client := http.Client{}
			res, err := client.Do(req)
			if err != nil {
				log.Printf("failed to retrieve teams: %s", err)
				forbidden(w)
				return
			}

			data, err := ioutil.ReadAll(res.Body)
			res.Body.Close()

			if err != nil {
				log.Printf("failed to read body of GitHub response: %s", err)
				forbidden(w)
				return
			}

			var info []map[string]json.RawMessage
			if err := json.Unmarshal(data, &info); err != nil {
				log.Printf("failed to decode json: %s", err.Error())
				forbidden(w)
				return
			}

			for _, userTeam := range info {
				var orgInfo map[string]interface{}
				if err := json.Unmarshal(userTeam["organization"], &orgInfo); err != nil {
					log.Printf("failed to decode json: %s", err.Error())
					forbidden(w)
					return
				}
				var teamInfo string
				if err := json.Unmarshal(userTeam["slug"], &teamInfo); err != nil {
					log.Printf("failed to decode json: %s", err.Error())
					forbidden(w)
					return
				}
				for _, team := range teamSlice {
					if orgInfo["login"] == team.organization && teamInfo == team.team {
						return
					}
				}
			}
		}

		log.Print("not a member of designated organizations/teams")
		forbidden(w)
		return
	}
}


func forbidden(w http.ResponseWriter) {
	w.WriteHeader(403)
	w.Write([]byte("Access denied"))
}
