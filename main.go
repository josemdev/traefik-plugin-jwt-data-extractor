package jwt_data_extractor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type FallbackType string

const (
	FallbackError  FallbackType = "error"
	FallbackPass   FallbackType = "pass"
	FallbackIp     FallbackType = "ip"
	FallbackHeader FallbackType = "header"
)

type Fallback struct {
	Type        FallbackType `yaml:"type,omitempty"`
	Value       string       `yaml:"value,omitempty"`
	KeepIfEmpty bool         `yaml:"keepIfEmpty,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	JwtHeaderName   string     `yaml:"jwtHeaderName,omitempty"`
	JwtField        string     `yaml:"jwtField,omitempty"`
	ValueHeaderName string     `yaml:"valueHeaderName,omitempty"`
	Fallbacks       []Fallback `yaml:"fallbacks,omitempty"`
	Debug           bool       `yaml:"debug,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// JWTDataExtractor is the main plugin structure.
type JWTDataExtractor struct {
	next http.Handler
	cfg  *Config
	name string
}

// New creates a new JWTDataExtractor plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &JWTDataExtractor{
		cfg:  config,
		next: next,
		name: name,
	}, nil
}

func (p *JWTDataExtractor) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(p.cfg.JwtHeaderName) == "" {
		p.logDebug("Empty jwt, falling back")
		p.ServeFallback(rw, req)
		return
	}

	rawHeader := req.Header.Get(p.cfg.JwtHeaderName)
	rawToken := ""
	if strings.HasPrefix(rawHeader, "Bearer ") {
		rawToken = rawHeader[len("Bearer "):]
	}
	parsedToken, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		p.logDebug("Could not parse non-empty jwt token, falling back: %s", err.Error())
		p.ServeFallback(rw, req)
		return
	}

	mapClaims := parsedToken.Claims.(jwt.MapClaims)
	if newHeaderValue, hasValue := mapClaims[p.cfg.JwtField]; hasValue {
		p.logDebug("JWT value on field %s was %v (of type %T)", p.cfg.JwtField, newHeaderValue, newHeaderValue)
		switch val := newHeaderValue.(type) {
		case string:
			req.Header.Set(p.cfg.ValueHeaderName, val)
			p.logDebug("TEST")
		case []string:
			if len(val) > 0 {
				req.Header.Set(p.cfg.ValueHeaderName, val[0])
				p.logDebug("TEST")
			} else {
				p.logDebug("JWT field value was an empty array, falling back")
				p.ServeFallback(rw, req)
				return
			}
		default:
			p.logDebug("JWT field value has an unexpected type, falling back")
			p.ServeFallback(rw, req)
			return
		}
	} else {
		p.logDebug("JWT field value does not hold field %s, falling back", p.cfg.JwtField)
		p.ServeFallback(rw, req)
		return
	}

	p.end(rw, req)
}

func (p *JWTDataExtractor) ServeFallback(rw http.ResponseWriter, req *http.Request) {
	if len(p.cfg.Fallbacks) == 0 {
		p.logDebug("Fallbacked because JWT was not set, invalid or has unexpected value on field. No fallback strategies, ignoring...")
	} else {
		p.logDebug("Fallbacked because JWT was not set, invalid or has unexpected value on field. Finding right fallback strategy")
		for i, fallback := range p.cfg.Fallbacks {
			p.logDebug("Strategy %d: %+v", i, fallback)
			var success bool
			switch fallback.Type {
			case FallbackError:
				rw.Header().Set("Content-Type", "text/plain")
				rw.WriteHeader(http.StatusBadRequest)
				rw.Write([]byte("Bad request"))
				return
			case FallbackPass:
				p.logDebug("Passing through")
				success = true
			case FallbackIp:
				req.Header.Set(p.cfg.ValueHeaderName, ipWithNoPort(req.RemoteAddr))
				success = true
			case FallbackHeader:
				headerValue := req.Header.Get(fallback.Value)
				if headerValue == "" && !fallback.KeepIfEmpty {
					p.logDebug("Header %s was empty, skipping...", fallback.Value)
					continue
				}
				req.Header.Set(p.cfg.ValueHeaderName, headerValue)
				success = true
			default:
				p.logDebug("Unknown fallback type, skipping...")
			}
			if success {
				p.logDebug("Fallback strategy %d was successful", i)
				break
			}
		}
	}
	p.end(rw, req)
}

func (p *JWTDataExtractor) logDebug(format string, args ...any) {
	if !p.cfg.Debug {
		return
	}
	os.Stderr.WriteString("[JWTDataExtractor middleware]: " + fmt.Sprintf(format, args...) + "\n")
}

func (p *JWTDataExtractor) end(rw http.ResponseWriter, req *http.Request) {
	p.logDebug("ending with request headers: %+v", req.Header)
	p.next.ServeHTTP(rw, req)
}

func ipWithNoPort(addr string) string {
	if colon := strings.LastIndex(addr, ":"); colon != -1 {
		return addr[:colon]
	}
	return addr
}

// Interface compliance
var (
	// Ensure the JWTDataExtractor struct implements the necessary interfaces
	_ http.Handler = (*JWTDataExtractor)(nil)
)

// Plugin struct to satisfy the plugin architecture
type Plugin struct {
	handler http.Handler
}

// NewPlugin initializes the plugin
func NewPlugin(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	jwtExtractor, err := New(ctx, next, config, name)
	if err != nil {
		return nil, err
	}
	return &Plugin{handler: jwtExtractor}, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.handler.ServeHTTP(rw, req)
}