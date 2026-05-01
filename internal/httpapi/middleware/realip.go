package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type trustedProxyMatcher struct {
	prefixes []netip.Prefix
}

func RealIP(trustedProxies []string) func(http.Handler) http.Handler {
	matcher := newTrustedProxyMatcher(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteAddr, ok := parseRemoteIP(r.RemoteAddr)
			if !ok || !matcher.Contains(remoteAddr) {
				next.ServeHTTP(w, r)
				return
			}

			if clientAddr, ok := clientAddrFromForwardedFor(r.Header.Get("X-Forwarded-For"), matcher); ok {
				r.RemoteAddr = clientAddr.String()
				next.ServeHTTP(w, r)
				return
			}

			if clientAddr, ok := parseRemoteIP(r.Header.Get("X-Real-IP")); ok {
				r.RemoteAddr = clientAddr.String()
			}

			next.ServeHTTP(w, r)
		})
	}
}

func newTrustedProxyMatcher(entries []string) trustedProxyMatcher {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, ok := parseTrustedProxyPrefix(entry)
		if ok {
			prefixes = append(prefixes, prefix)
		}
	}

	return trustedProxyMatcher{prefixes: prefixes}
}

func (m trustedProxyMatcher) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range m.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseTrustedProxyPrefix(value string) (netip.Prefix, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return netip.Prefix{}, false
	}

	if prefix, err := netip.ParsePrefix(trimmed); err == nil {
		return prefix.Masked(), true
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Prefix{}, false
	}

	bits := 128
	if addr.Is4() {
		bits = 32
	}

	return netip.PrefixFrom(addr.Unmap(), bits), true
}

func clientAddrFromForwardedFor(header string, matcher trustedProxyMatcher) (netip.Addr, bool) {
	if strings.TrimSpace(header) == "" {
		return netip.Addr{}, false
	}

	parts := strings.Split(header, ",")
	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, ok := parseRemoteIP(part)
		if !ok {
			return netip.Addr{}, false
		}
		addresses = append(addresses, addr)
	}

	for i := len(addresses) - 1; i >= 0; i-- {
		if !matcher.Contains(addresses[i]) {
			return addresses[i], true
		}
	}

	if len(addresses) == 0 {
		return netip.Addr{}, false
	}

	return addresses[0], true
}

func parseRemoteIP(value string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return netip.Addr{}, false
	}

	host, _, err := net.SplitHostPort(trimmed)
	if err == nil {
		trimmed = host
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr.Unmap(), true
}
