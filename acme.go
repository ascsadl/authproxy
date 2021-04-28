package main

import (
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/acme/autocert"
)

func ListenAndServe(conf Config, handler http.Handler) error {
	// Make a list of all unique hosts
	var hosts []string
	added := make(map[string]bool)
	for _, p := range conf.Proxies {
		u, err := url.Parse(p.Src)
		if err != nil {
			continue
		}
		host := u.Host
		if !added[host] {
			hosts = append(hosts, host)
			added[host] = true
		}
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(conf.CertsDir),
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      conf.CertsEmail,
	}
	s := &http.Server{
		Addr:      ":https",
		Handler:   handler,
		TLSConfig: m.TLSConfig(),
	}

	// Listen on port 80 for HTTPS challenge responses, otherwise redirect to HTTPS
	log.Printf("Listening on :http")
	go http.ListenAndServe(":http", m.HTTPHandler(nil))

	log.Printf("Listening on %s", s.Addr)
	return s.ListenAndServeTLS("", "")
}
