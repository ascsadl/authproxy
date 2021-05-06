package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	// For Microsoft authentication
	TenantId     string `json:"tenant_id"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	SessionKey []byte `json:"session_key"` // Key for the session cookie
	CertsDir   string `json:"certs_dir"`   // Directory to store SSL certificates
	CertsEmail string `json:"certs_email"` // Contact email for SSL registration

	Proxies []ProxyConfig `json:"proxies"`
}

type ProxyConfig struct {
	Src   string `json:"src"`
	Group string `json:"group,omitempty"`
	Dst   string `json:"dst"`
}

func ReadConfig(file string) (Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	var conf Config
	dec := json.NewDecoder(f)
	err = dec.Decode(&conf)
	return conf, err
}
