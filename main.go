package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/sessions"
)

const (
	UserHeader   = "ASCSA-User"
	GroupsHeader = "ASCSA-Groups"
)

type AuthProxy struct {
	conf        Config
	cookieStore *sessions.CookieStore
	proxies     []*ReverseProxy
}

func NewAuthProxy(conf Config) *AuthProxy {
	cookieStore := sessions.NewCookieStore(conf.SessionKey)
	cookieStore.Options.Secure = true

	var proxies []*ReverseProxy
	for _, p := range conf.Proxies {
		src, err := url.Parse(p.Src)
		if err != nil {
			log.Fatalf("Invalid src URL in config: %s", p.Src)
		}
		dst, err := url.Parse(p.Dst)
		if err != nil {
			log.Fatalf("Invalid dst URL in config: %s", p.Dst)
		}
		proxy := NewReverseProxy(src, dst, p.Group)
		proxies = append(proxies, proxy)
	}

	return &AuthProxy{
		conf:        conf,
		cookieStore: cookieStore,
		proxies:     proxies,
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
	redirectURI := fmt.Sprintf("https://%s/signin-callback", r.Host)
	u := AuthorizationCodeRequestURL(ap.conf.TenantId, ap.conf.ClientId, redirectURI)
	http.Redirect(w, r, u, http.StatusFound)
}

func (ap *AuthProxy) serveSigninCallback(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	code := r.URL.Query().Get("code")
	redirectURI := fmt.Sprintf("https://%s/signin-callback", r.Host)
	token, err := RequestAccessToken(ap.conf.TenantId, ap.conf.ClientId, ap.conf.ClientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userName, displayName, err := GetUser(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, err := GetUserGroups(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Do not allow spaces in groups
	for i, group := range groups {
		groups[i] = strings.ReplaceAll(group, " ", "")
	}

	session.Values["username"] = userName
	session.Values["displayname"] = displayName
	session.Values["groups"] = groups
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (ap *AuthProxy) serveSignoutCallback(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	session.Values = nil
	session.Save(r, w)

	bookmark := r.URL.Query().Get("bookmark")
	if bookmark == "" {
		bookmark = fmt.Sprintf("https://%s/", r.Host)
	}
	http.Redirect(w, r, bookmark, http.StatusFound)
}

func (ap *AuthProxy) serveReverseProxy(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	userName, _ := session.Values["username"].(string)
	displayName, _ := session.Values["displayname"].(string)
	groups, _ := session.Values["groups"].([]string)

	if userName != "" {
		r.Header.Set(UserHeader, fmt.Sprintf("%s %s", userName, displayName))
		r.Header.Set(GroupsHeader, strings.Join(groups, " "))
	} else {
		r.Header.Set(UserHeader, "")
		r.Header.Set(GroupsHeader, "")
	}

	for _, p := range ap.proxies {
		if r.Host == p.host && strings.HasPrefix(r.URL.Path, p.path) {
			if p.Access(groups) {
				p.ServeHTTP(w, r)
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
			return
		}
	}
	http.Error(w, "Not Found", http.StatusNotFound)
}

type ReverseProxy struct {
	*httputil.ReverseProxy
	host  string
	path  string
	group string
}

func NewReverseProxy(src, dst *url.URL, group string) *ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(dst)
	return &ReverseProxy{
		ReverseProxy: rp,
		host:         src.Host,
		path:         src.Path,
		group:        group,
	}
}

func (p *ReverseProxy) Access(groups []string) bool {
	if p.group == "" {
		return true // All groups allowed
	} else if p.group == "*" {
		return len(groups) > 0 // Any (non-public) group allowed
	} else {
		for _, group := range groups {
			if group == p.group {
				return true
			}
		}
	}
	return false
}

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
