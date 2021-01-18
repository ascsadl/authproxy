package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
)

const apiScope = "user.read directory.accessAsUser.all"

type AuthProxy struct {
	conf         Config
	cookieStore  *sessions.CookieStore
	reverseProxy *httputil.ReverseProxy
	manageProxy  *httputil.ReverseProxy
}

func NewAuthProxy(conf Config) *AuthProxy {
	cookieStore := sessions.NewCookieStore(conf.SessionKey)
	cookieStore.Options.Secure = true

	reverseProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", conf.TargetPort),
	})
	manageProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", conf.ManagePort),
	})

	return &AuthProxy{
		conf:         conf,
		cookieStore:  cookieStore,
		reverseProxy: reverseProxy,
		manageProxy:  manageProxy,
	}
}

func (ap *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Ignore errors, we'll just get a new session on error
	session, _ := ap.cookieStore.Get(r, "session")

	switch r.URL.Path {
	case "/signin":
		log.Printf("%s %s: %s", r.Method, r.URL, r.RemoteAddr)
		ap.serveSignin(w, r)
	case "/signin-callback":
		// Do not log the URL query, since it contains sensitive info
		log.Printf("%s %s: %s", r.Method, r.URL.Path, r.RemoteAddr)
		ap.serveSigninCallback(w, r, session)
	case "/signout":
		log.Printf("%s %s: %s", r.Method, r.URL.Path, r.RemoteAddr)
		ap.serveSignoutCallback(w, r, session)
	default:
		log.Printf("%s %s: %s", r.Method, r.URL.Path, r.RemoteAddr)
		ap.serveReverseProxy(w, r, session)
	}
}

func (ap *AuthProxy) serveSignin(w http.ResponseWriter, r *http.Request) {
	redirectURI := ap.urlForPath("/signin-callback")
	u := AuthorizationCodeRequestURL(ap.conf.TenantId, ap.conf.ClientId, redirectURI)
	http.Redirect(w, r, u, http.StatusFound)
}

func (ap *AuthProxy) serveSigninCallback(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	code := r.URL.Query().Get("code")
	redirectURI := ap.urlForPath("/signin-callback")
	token, err := RequestAccessToken(ap.conf.TenantId, ap.conf.ClientId, ap.conf.ClientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user, err := GetUserDisplayName(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, err := GetUserGroups(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["user"] = user
	session.Values["groups"] = groups
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (ap *AuthProxy) serveSignoutCallback(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	session.Values = nil
	session.Save(r, w)

	bookmark := r.URL.Query().Get("bookmark")
	if bookmark == "" {
		bookmark = ap.urlForPath("/")
	}
	http.Redirect(w, r, bookmark, http.StatusFound)
}

func (ap *AuthProxy) serveReverseProxy(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	user, groups := decodeSession(session)
	groups = append(groups, "Public")
	if user != "" {
		r.Header.Set("ASCSA-User", user)
		r.Header.Set("ASCSA-Groups", strings.Join(groups, ","))
	} else {
		r.Header.Set("ASCSA-User", "")
		r.Header.Set("ASCSA-Groups", "Public")
	}

	if strings.HasPrefix(r.URL.Path, ap.conf.ManagePath) {
		ap.manageProxy.ServeHTTP(w, r)
	} else {
		ap.reverseProxy.ServeHTTP(w, r)
	}
}

func (ap *AuthProxy) urlForPath(path string) string {
	u := url.URL{
		Scheme: "https",
		Host:   ap.conf.Host,
		Path:   path,
	}
	return u.String()
}

func decodeSession(session *sessions.Session) (string, []string) {
	user, _ := session.Values["user"].(string)
	groups, _ := session.Values["groups"].([]string)
	return user, groups
}

func main() {
	confPath := flag.String("conf", "", "Path to config file")
	flag.Parse()

	if *confPath == "" {
		log.Fatal("Missing configuration file")
	}
	conf, err := ReadConfig(*confPath)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}

	h := NewAuthProxy(conf)

	log.Fatal(ListenAndServe(conf, h))
}
