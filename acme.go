package main

import (
	"log"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

func ListenAndServe(conf Config, handler http.Handler) error {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(conf.CertsDir),
		HostPolicy: autocert.HostWhitelist(conf.Host),
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
