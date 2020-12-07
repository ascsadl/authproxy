package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type UserResponse struct {
	Id          string `json:"id"`
	UserName    string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
}

func getUserInfo(token string) (string, error) {
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

func getUserGroups(token string) ([]string, error) {
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
