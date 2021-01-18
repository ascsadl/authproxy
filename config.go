package main

// The format of the config file is:
//     KEY = VAL
// No quotes are needed, empty lines and lines starting with # are ignored

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Host       string
	TargetPort int    // Reverse proxy to this local port for main site
	ManagePort int    // Reverse proxy to this local port for manage site
	ManagePath string // Path for manage site

	// For Microsoft authentication
	TenantId     string
	ClientId     string
	ClientSecret string

	SessionKey []byte // Key for the session cookie
	CertsDir   string // Directory to store SSL certificates
	CertsEmail string // Contact email for SSL registration
}

func ReadConfig(file string) (Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineno := 0
	c := Config{}

	for scanner.Scan() {
		lineno++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return c, fmt.Errorf("Invalid config entry on line %d", lineno)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "host":
			c.Host = val
		case "target_port":
			port, err := strconv.Atoi(val)
			if err != nil {
				return c, fmt.Errorf("Invalid config entry on line %d: %s", lineno, err)
			}
			c.TargetPort = port
		case "manage_port":
			port, err := strconv.Atoi(val)
			if err != nil {
				return c, fmt.Errorf("Invalid config entry on line %d: %s", lineno, err)
			}
			c.ManagePort = port
		case "manage_path":
			c.ManagePath = val
		case "tenant_id":
			c.TenantId = val
		case "client_id":
			c.ClientId = val
		case "client_secret":
			c.ClientSecret = val
		case "session_key":
			c.SessionKey = []byte(val)
		case "certs_dir":
			c.CertsDir = val
		case "certs_email":
			c.CertsEmail = val
		default:
			return c, fmt.Errorf("Invalid config entry on line %d", lineno)
		}
	}

	return c, nil
}
