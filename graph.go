package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func AuthorizationCodeRequestURL(tenant, clientId, redirectURI string) string {
	u := &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   fmt.Sprintf("/%s/oauth2/v2.0/authorize", tenant),
	}
	q := u.Query()
	q.Set("client_id", clientId)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_mode", "query")
	q.Set("scope", apiScope)
	u.RawQuery = q.Encode()
	return u.String()
}

type AccessTokenResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func RequestAccessToken(tenant, clientId, clientSecret, code, redirectURI string) (string, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   fmt.Sprintf("/%s/oauth2/v2.0/token", tenant),
	}

	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("grant_type", "authorization_code")
	data.Set("scope", apiScope)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_secret", clientSecret)

	resp, err := http.PostForm(u.String(), data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var r AccessTokenResponse
	err = dec.Decode(&r)
	if err != nil {
		return "", err
	}
	return r.AccessToken, nil
}

type UserResponse struct {
	Id          string `json:"id"`
	UserName    string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
}

func GetUserDisplayName(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var r UserResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&r)
	return r.DisplayName, err
}

type GroupsResponse struct {
	Groups []struct {
		Type string `json:"@odata.type"`
		Id   string `json:"id"`
		Name string `json:"displayName"`
	} `json:"value"`
}

func GetUserGroups(token string) ([]string, error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r GroupsResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&r)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, v := range r.Groups {
		if v.Type == "#microsoft.graph.group" {
			groups = append(groups, v.Name)
		}
	}
	return groups, nil
}
