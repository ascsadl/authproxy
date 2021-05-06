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

const (
	UserHeader   = "ASCSA-User"
	GroupsHeader = "ASCSA-Groups"
)

type AuthProxy struct {
	conf        Config
	cookieStore *sessions.CookieStore
	vhosts      map[string][]Proxy
}

type Proxy struct {
	Path    string
	Group   string
	Handler ProxyHandler
}

type ProxyHandler interface {
	Serve(w http.ResponseWriter, r *http.Request, session *sessions.Session)
}

func NewAuthProxy(conf Config) *AuthProxy {
	cookieStore := sessions.NewCookieStore(conf.SessionKey)
	cookieStore.Options.Secure = true

	vhosts := make(map[string][]Proxy)
	for _, p := range conf.Proxies {
		src, err := url.Parse(p.Src)
		if err != nil {
			log.Fatalf("Invalid src URL in config: %s", p.Src)
		}

		switch p.Dst {
		case "|signin":
			signin := Proxy{
				Path: src.Path,
				Handler: &SigninHandler{
					TenantId: conf.TenantId,
					ClientId: conf.ClientId,
				},
			}
			signinCallback := Proxy{
				Path: src.Path + "-callback",
				Handler: &SigninCallbackHandler{
					TenantId:     conf.TenantId,
					ClientId:     conf.ClientId,
					ClientSecret: conf.ClientSecret,
				},
			}
			vhosts[src.Host] = append(vhosts[src.Host], signinCallback, signin)

		case "|signout":
			proxy := Proxy{Path: src.Path, Handler: &SignoutHandler{}}
			vhosts[src.Host] = append(vhosts[src.Host], proxy)

		default:
			dst, err := url.Parse(p.Dst)
			if err != nil {
				log.Fatalf("Invalid dst URL in config: %s", p.Dst)
			}
			proxy := Proxy{
				Path:    src.Path,
				Group:   p.Group,
				Handler: NewReverseHandler(dst),
			}
			vhosts[src.Host] = append(vhosts[src.Host], proxy)
		}
	}

	return &AuthProxy{
		conf:        conf,
		cookieStore: cookieStore,
		vhosts:      vhosts,
	}
}

func (ap *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Ignore errors, we'll just get a new session on error
	session, _ := ap.cookieStore.Get(r, "session")

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

	for _, proxy := range ap.vhosts[r.Host] {
		if strings.HasPrefix(r.URL.Path, proxy.Path) {
			if ap.canAccess(groups, proxy.Group) {
				proxy.Handler.Serve(w, r, session)
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
			return
		}
	}
	http.Error(w, "Not Found", http.StatusNotFound)
}

func (ap *AuthProxy) canAccess(groups []string, group string) bool {
	if group == "" {
		return true // All groups allowed
	} else if group == "*" {
		return len(groups) > 0 // Any (non-public) group allowed
	} else {
		for _, group := range groups {
			if group == group {
				return true
			}
		}
	}
	return false
}

type ReverseHandler struct {
	*httputil.ReverseProxy
}

func NewReverseHandler(dst *url.URL) *ReverseHandler {
	return &ReverseHandler{
		ReverseProxy: httputil.NewSingleHostReverseProxy(dst),
	}
}

func (p *ReverseHandler) Serve(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	log.Printf("%s %s: %s", r.Method, r.URL, r.RemoteAddr)
	p.ServeHTTP(w, r)
}

type SigninHandler struct {
	TenantId     string
	ClientId     string
	ClientSecret string
}

func (h *SigninHandler) Serve(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	log.Printf("%s %s: %s", r.Method, r.URL, r.RemoteAddr)
	redirectURI := fmt.Sprintf("https://%s%s-callback", r.Host, r.URL.Path)
	u := AuthorizationCodeRequestURL(h.TenantId, h.ClientId, redirectURI)
	http.Redirect(w, r, u, http.StatusFound)
}

type SigninCallbackHandler struct {
	TenantId     string
	ClientId     string
	ClientSecret string
}

func (h *SigninCallbackHandler) Serve(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	// Do not log the URL query, since it contains sensitive info
	log.Printf("%s %s: %s", r.Method, r.URL.Path, r.RemoteAddr)
	code := r.URL.Query().Get("code")
	redirectURI := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
	token, err := RequestAccessToken(h.TenantId, h.ClientId, h.ClientSecret, code, redirectURI)
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

type SignoutHandler struct{}

func (h *SignoutHandler) Serve(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	log.Printf("%s %s: %s", r.Method, r.URL, r.RemoteAddr)
	session.Values = nil
	session.Save(r, w)

	bookmark := r.URL.Query().Get("bookmark")
	if bookmark == "" {
		bookmark = fmt.Sprintf("https://%s/", r.Host)
	}
	http.Redirect(w, r, bookmark, http.StatusFound)
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
