package auth

import (
	"net"
	"net/http"
	"runtime"
)

func GetClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	if ip == "::1" {
		ip = "127.0.0.1"
	}
	return ip
}

func GetOS() string {
	os := runtime.GOOS
	return os
}
