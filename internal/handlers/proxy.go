// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Originally from https://github.com/gorilla/handlers with following license
// https://raw.githubusercontent.com/gorilla/handlers/master/LICENSE, forked
// and heavily modified for MinIO's internal needs.

package handlers

import (
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/minio/minio/internal/config"
	"github.com/minio/pkg/v3/env"
)

var (
	// De-facto standard header keys.
	xForwardedFor    = http.CanonicalHeaderKey("X-Forwarded-For")
	xForwardedHost   = http.CanonicalHeaderKey("X-Forwarded-Host")
	xForwardedPort   = http.CanonicalHeaderKey("X-Forwarded-Port")
	xForwardedProto  = http.CanonicalHeaderKey("X-Forwarded-Proto")
	xForwardedScheme = http.CanonicalHeaderKey("X-Forwarded-Scheme")
	xRealIP          = http.CanonicalHeaderKey("X-Real-IP")
)

var (
	// RFC7239 defines a new "Forwarded: " header designed to replace the
	// existing use of X-Forwarded-* headers.
	// e.g. Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43
	forwarded = http.CanonicalHeaderKey("Forwarded")
	// Allows for a sub-match of the first value after 'for=' to the next
	// comma, semi-colon or space. The match is case-insensitive.
	forRegex     = regexp.MustCompile(`(?i)(?:for=)([^(;|,| )]+)(.*)`)
	forItemRegex = regexp.MustCompile(`(?i)for=([^;, ]+)`)
	// Allows for a sub-match for the first instance of scheme (http|https)
	// prefixed by 'proto='. The match is case-insensitive.
	protoRegex = regexp.MustCompile(`(?i)^(;|,| )+(?:proto=)(https|http)`)
)

// Used to disable all processing of the X-Forwarded-For header in source IP discovery.
var enableXFFHeader = env.Get("_MINIO_API_XFF_HEADER", config.EnableOn) == config.EnableOn

// trustedProxies restricts forwarding header trust to configured proxy IPs/CIDRs.
// Empty by default so direct clients cannot spoof aws:SourceIp or rate-limit keys.
var trustedProxies = parseTrustedProxies(env.Get("MINIO_API_TRUSTED_PROXIES", env.Get("_MINIO_API_TRUSTED_PROXIES", "")))

func parseTrustedProxies(spec string) []netip.Prefix {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	var prefixes []netip.Prefix
	for entry := range strings.SplitSeq(spec, ",") {
		s := strings.TrimSpace(entry)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
		}
	}
	return prefixes
}

func isTrustedProxy(remoteAddr string) bool {
	if len(trustedProxies) == 0 || remoteAddr == "" {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func isIPInTrustedProxies(raw string) bool {
	host := strings.Trim(strings.TrimSpace(raw), `"[]`)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// GetSourceScheme retrieves the scheme from the X-Forwarded-Proto and RFC7239
// Forwarded headers (in that order).
func GetSourceScheme(r *http.Request) string {
	var scheme string

	// Retrieve the scheme from X-Forwarded-Proto.
	if proto := r.Header.Get(xForwardedProto); proto != "" {
		scheme = strings.ToLower(strings.TrimSpace(proto))
	} else if proto = r.Header.Get(xForwardedScheme); proto != "" {
		scheme = strings.ToLower(strings.TrimSpace(proto))
	} else if proto := r.Header.Get(forwarded); proto != "" {
		if match := forRegex.FindStringSubmatch(proto); len(match) > 1 {
			if match = protoRegex.FindStringSubmatch(match[2]); len(match) > 1 {
				scheme = strings.ToLower(match[2])
			}
		}
	}

	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme
}

// GetSourceIPFromHeaders retrieves the IP from the X-Forwarded-For, X-Real-IP
// and RFC7239 Forwarded headers (in that order) only when r.RemoteAddr is a trusted proxy.
func GetSourceIPFromHeaders(r *http.Request) string {
	if !isTrustedProxy(r.RemoteAddr) {
		return ""
	}
	var addr string

	if enableXFFHeader {
		if xffVals := r.Header.Values(xForwardedFor); len(xffVals) > 0 {
			// Join all X-Forwarded-For header lines before walking right-to-left:
			// proxies that append a second header line instead of coalescing put
			// the trusted hop in the last header, while r.Header.Get reads only [0].
			fwd := strings.Join(xffVals, ",")
			parts := strings.Split(fwd, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(parts[i])
				if candidate == "" {
					continue
				}
				if !isIPInTrustedProxies(candidate) {
					addr = candidate
					break
				}
				addr = candidate
			}
		}
	}

	if addr == "" {
		if fwd := r.Header.Get(xRealIP); fwd != "" {
			// X-Real-IP should only contain one IP address (the client making the
			// request).
			addr = strings.TrimSpace(fwd)
		} else if fwdVals := r.Header.Values(forwarded); len(fwdVals) > 0 {
			fwd := strings.Join(fwdVals, ", ")
			matches := forItemRegex.FindAllStringSubmatch(fwd, -1)
			for i := len(matches) - 1; i >= 0; i-- {
				candidate := strings.Trim(strings.TrimSpace(matches[i][1]), `"`)
				if candidate == "" {
					continue
				}
				if !isIPInTrustedProxies(candidate) {
					addr = candidate
					break
				}
				addr = candidate
			}
		}
	}

	return addr
}

// GetSourceIPRaw retrieves the IP from the request headers
// and falls back to r.RemoteAddr when necessary.
// however returns without bracketing.
func GetSourceIPRaw(r *http.Request) string {
	addr := GetSourceIPFromHeaders(r)
	if addr == "" {
		addr = r.RemoteAddr
	}

	// Default to remote address if headers not set.
	raddr, _, _ := net.SplitHostPort(addr)
	if raddr == "" {
		return addr
	}
	return raddr
}

// GetSourceIP retrieves the IP from the request headers
// and falls back to r.RemoteAddr when necessary.
func GetSourceIP(r *http.Request) string {
	addr := GetSourceIPRaw(r)
	if strings.ContainsRune(addr, ':') {
		return "[" + addr + "]"
	}
	return addr
}
