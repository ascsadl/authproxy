package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/acme/autocert"
)

var (
	rootDirFlag = flag.String("root", "/opt/ascsa", "Path to root dir")
)

const apiScope = "user.read directory.accessAsUser.all"

type AuthProxy struct {
	host         string
	tenantId     string
	clientId     string
	clientSecret string

	cookieStore  *sessions.CookieStore
	reverseProxy *httputil.ReverseProxy
}

func NewAuthProxy(config map[string]string) *AuthProxy {
	target := &url.URL{
		Scheme: "http",
		Host:   config["target_host"],
	}

	cookieStore := sessions.NewCookieStore([]byte(config["session_key"]))
	cookieStore.Options.Secure = true

	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	return &AuthProxy{
		host:         config["host"],
		tenantId:     config["tenant_id"],
		clientId:     config["client_id"],
		clientSecret: config["client_secret"],
		cookieStore:  cookieStore,
		reverseProxy: reverseProxy,
	}
}

func (ap *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	// Ignore errors, we'll just get a new session on error
	session, _ := ap.cookieStore.Get(r, "session")

	switch r.URL.Path {
	case "/signin":
		ap.serveSignin(w, r)
	case "/signin-callback":
		ap.serveSigninCallback(w, r, session)
	case "/signout":
		ap.serveSignoutCallback(w, r, session)
	default:
		ap.serveReverseProxy(w, r, session)
	}
}

func (ap *AuthProxy) serveSignin(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse("https://login.microsoftonline.com/")
	u.Path = fmt.Sprintf("/%s/oauth2/v2.0/authorize", ap.tenantId)
	q := u.Query()
	q.Set("client_id", ap.clientId)
	q.Set("response_type", "code")
	q.Set("redirect_uri", ap.urlForPath("/signin-callback"))
	q.Set("response_mode", "query")
	q.Set("scope", apiScope)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (ap *AuthProxy) serveSigninCallback(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	code := r.URL.Query().Get("code")

	u, _ := url.Parse("https://login.microsoftonline.com/")
	u.Path = fmt.Sprintf("/%s/oauth2/v2.0/token", ap.tenantId)

	data := url.Values{}
	data.Set("client_id", ap.clientId)
	data.Set("grant_type", "authorization_code")
	data.Set("scope", apiScope)
	data.Set("code", code)
	data.Set("redirect_uri", ap.urlForPath("/signin-callback"))
	data.Set("client_secret", ap.clientSecret)

	resp, err := http.PostForm(u.String(), data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var tokenResp TokenResponse
	err = dec.Decode(&tokenResp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user, err := getUserInfo(tokenResp.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, err := getUserGroups(tokenResp.AccessToken)
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
	user := getSessionValue(session, "user")
	groups := getSessionValues(session, "groups")
	groups = append(groups, "Public")
	if user != "" {
		r.Header.Set("ASCSA-User", user)
		r.Header.Set("ASCSA-Groups", strings.Join(groups, ","))
	} else {
		r.Header.Set("ASCSA-User", "")
		r.Header.Set("ASCSA-Groups", "Public")
	}
	ap.reverseProxy.ServeHTTP(w, r)
}

func (ap *AuthProxy) urlForPath(path string) string {
	u := url.URL{
		Scheme: "https",
		Host:   ap.host,
		Path:   path,
	}
	return u.String()
}

func getSessionValue(session *sessions.Session, key string) string {
	switch val := session.Values[key].(type) {
	case string:
		return val
	default:
		return ""
	}
}

func getSessionValues(session *sessions.Session, key string) []string {
	switch val := session.Values[key].(type) {
	case []string:
		return val
	default:
		return nil
	}
}

func readConfig(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	conf := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		conf[key] = val
	}

	return conf, nil
}

func main() {
	flag.Parse()

	confPath := filepath.Join(*rootDirFlag, "ascsa.conf")
	config, err := readConfig(confPath)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}

	ap := NewAuthProxy(config)

	dirCache := filepath.Join(*rootDirFlag, "letsencrypt")
	m := &autocert.Manager{
		Cache:      autocert.DirCache(dirCache),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(config["host"]),
	}
	s := &http.Server{
		Addr:      ":https",
		Handler:   ap,
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	go http.ListenAndServe(":http", m.HTTPHandler(nil))

	log.Fatal(s.ListenAndServeTLS("", ""))
}
