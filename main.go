package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret []byte

type AuthClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func createToken(userID string) (string, error) {
	expirationTime := time.Now().Add(time.Hour)
	claims := &AuthClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenString string) (*AuthClaims, error) {
	claims := &AuthClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == LoginURL {
			next.ServeHTTP(w, r)
			return
		}

		var tokenString string

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}

		if tokenString == "" {
			cookie, e := r.Cookie(CookieName)
			if e == nil {
				tokenString = cookie.Value
			}
		}

		if tokenString != "" {
			_, err := validateToken(tokenString)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
		}

		http.Redirect(w, r, LoginURL, http.StatusFound)
	})
}

func computeToken(username string, password string, salt string) []byte {
	hash := sha256.New()
	hash.Write([]byte(username + ":" + password + ":" + salt))
	return hash.Sum(nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<10) // 10KB

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		computed := computeToken(username, password, Salt)

		if subtle.ConstantTimeCompare(computed, Token) != 1 {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		tokenString, err := createToken(username)
		if err != nil {
			http.Error(w, "Failed to create token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    tokenString,
			Path:     "/",
			Expires:  time.Now().Add(time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`
        <h1>Login Page</h1>
        <form method="post">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username"><br><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
    `))
}

var acceptedIpRanges = []string{
	// Cloudflare IPv4 Ranges
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// Local Networks
	"192.168.0.0/16",
}

var allowedIPNets []*net.IPNet

var LocalNetwork = net.IPNet{
	IP:   net.IPv4(192, 168, 0, 0),
	Mask: net.CIDRMask(16, 32),
}

func init() {
	for _, cidr := range acceptedIpRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("Invalid CIDR configuration: " + err.Error())
		}
		allowedIPNets = append(allowedIPNets, ipNet)
	}
}

func ipWhitelistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// println("Login attempt from IP:", ip, r.Host)

		host, _, err := net.SplitHostPort(ip)
		if err != nil {
			host = ip
		}

		requestIP := net.ParseIP(host)
		if requestIP == nil {
			http.Error(w, "Invalid IP Address", http.StatusForbidden)
			return
		}

		if r.Host != HostURL && !LocalNetwork.Contains(requestIP) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		isAllowed := false
		for _, ipNet := range allowedIPNets {
			if ipNet.Contains(requestIP) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	jwtSecret = make([]byte, 32)
	rand.Read(jwtSecret)

	target, _ := url.Parse(TargetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	mux := http.NewServeMux()
	mux.Handle(LoginURL, http.HandlerFunc(loginHandler))

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	authProxy := authMiddleware(proxyHandler)
	mux.Handle("/", authProxy)
	finalHandler := ipWhitelistMiddleware(mux)

	http.ListenAndServeTLS("0.0.0.0:6853", CertFile, KeyFile, finalHandler)
}
