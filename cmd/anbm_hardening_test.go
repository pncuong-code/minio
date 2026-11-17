// Copyright (c) 2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Regression tests for the ANBM security hardening set.

package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/pkg/v3/policy"
)

// ANBM-001: a client-supplied header or query value must not override the
// server-derived aws:SourceIp condition value.
func TestANBMConditionKeysNotClientOverridable(t *testing.T) {
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],` +
		`"Resource":["arn:aws:s3:::b/*"],"Condition":{"IpAddress":{"aws:SourceIp":"10.9.9.0/24"}}}]}`
	p, err := policy.ParseConfig(strings.NewReader(pol))
	if err != nil {
		t.Fatal(err)
	}
	eval := func(spoofHeader, spoofQuery bool) bool {
		target := "http://x/b/o"
		if spoofQuery {
			target += "?SourceIp=10.9.9.9"
		}
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = "203.0.113.5:1234" // real client IP, outside the allowlist
		if spoofHeader {
			r.Header.Set("SourceIp", "10.9.9.9")
		}
		return p.IsAllowed(policy.Args{
			AccountName: "u", Action: policy.GetObjectAction, BucketName: "b", ObjectName: "o",
			ConditionValues: getConditionValues(r, "", auth.Credentials{AccessKey: "u"}),
		})
	}
	if eval(false, false) {
		t.Fatal("request from an IP outside the allowlist should be denied")
	}
	if eval(true, false) {
		t.Fatal("ANBM-001: spoofed SourceIp header overrode the real client IP")
	}
	if eval(false, true) {
		t.Fatal("ANBM-001: spoofed SourceIp query value overrode the real client IP")
	}
}

// ANBM-002: isPutRetentionAllowed must not honour the bypass-governance header
// unless the caller actually holds s3:BypassGovernanceRetention, whatever the
// requested mode. With deny-by-default IAM (no policy loaded) and no bypass
// permission, a COMPLIANCE put backed only by the header must be denied.
func TestANBMRetentionBypassNeedsPermission(t *testing.T) {
	if globalIAMSys == nil {
		globalIAMSys = NewIAMSys()
	}
	r := httptest.NewRequest(http.MethodPut, "http://x/b/o?retention", nil)
	r.Header.Set(xhttp.AmzObjectLockBypassGovernance, "true")
	cred := auth.Credentials{AccessKey: "lowpriv"}
	// COMPLIANCE mode, header present, no permissions: must be denied.
	if s3Err := isPutRetentionAllowed("b", "o", 1, UTCNow(), "COMPLIANCE", true, r, cred, false); s3Err == ErrNone {
		t.Fatal("ANBM-002: bypass-governance header alone granted a retention write")
	}
}

// ANBM-003: fan-out metadata guard must reject internal and object-lock keys.
func TestANBMFanOutReservedMetadata(t *testing.T) {
	for _, k := range []string{
		"X-Minio-Internal-actual-size",
		"x-minio-internal-foo",
		"X-Amz-Object-Lock-Mode",
		"x-amz-object-lock-retain-until-date",
	} {
		if !isReservedFanOutMetadata(k) {
			t.Fatalf("ANBM-003: reserved key %q was not rejected", k)
		}
	}
	for _, k := range []string{"x-amz-meta-user", "content-type", "colour"} {
		if isReservedFanOutMetadata(k) {
			t.Fatalf("ANBM-003: ordinary key %q was wrongly rejected", k)
		}
	}
}

// ANBM-012: the ServerInfo env redaction must cover secret families the old
// heuristic missed.
func TestANBMSensitiveEnvRedaction(t *testing.T) {
	secret := []string{
		"MINIO_IDENTITY_OPENID_CLIENT_SECRET",
		"MINIO_NOTIFY_WEBHOOK_AUTH_TOKEN",
		"MINIO_NOTIFY_POSTGRES_CONNECTION_STRING",
		"MINIO_NOTIFY_MYSQL_DSN_STRING",
		"MINIO_CERT_PASSWD",
		"MINIO_SUBNET_LICENSE",
		"MINIO_ROOT_PASSWORD",
		"MINIO_SECRET_KEY",
	}
	for _, k := range secret {
		if !isSensitiveEnvKey(k) {
			t.Fatalf("ANBM-012: %q should be redacted", k)
		}
	}
	for _, k := range []string{"MINIO_VOLUMES", "MINIO_REGION", "MINIO_BROWSER"} {
		if isSensitiveEnvKey(k) {
			t.Fatalf("ANBM-012: %q should not be redacted", k)
		}
	}
	// A plain *_URL suffix must NOT be treated as secret: these are non-secret
	// endpoints that monitoring / support bundles need.
	for _, k := range []string{
		"MINIO_SERVER_URL", "MINIO_BROWSER_REDIRECT_URL",
		"MINIO_IDENTITY_OPENID_CONFIG_URL", "MINIO_PROMETHEUS_URL",
	} {
		if isSensitiveEnvKey(k) {
			t.Fatalf("ANBM-012: non-secret %q should not be redacted", k)
		}
	}
}

// ANBM-006: trace query redaction must mask STS bearer tokens and presigned
// SigV4 material (which live in RawQuery on the Queries()-matched routes),
// while leaving ordinary request parameters intact.
func TestANBMTraceQueryRedaction(t *testing.T) {
	secret := []string{
		"WebIdentityToken=eyJhbGciOi.header.sig",
		"Token=super-secret-grant",
		"X-Amz-Security-Token=FwoGZXIvYXdz",
		"X-Amz-Signature=deadbeefcafe",
		"X-Amz-Credential=AKIA/20260101/us-east-1/s3/aws4_request",
	}
	for _, q := range secret {
		got := redactTraceQuery(q)
		if strings.Contains(got, "secret") || strings.Contains(got, "eyJhbGciOi") ||
			strings.Contains(got, "FwoGZXIvYXdz") || strings.Contains(got, "deadbeefcafe") ||
			strings.Contains(got, "AKIA") {
			t.Fatalf("ANBM-006: query credential leaked through trace: %q -> %q", q, got)
		}
		if !strings.Contains(got, "*REDACTED*") {
			t.Fatalf("ANBM-006: expected redaction marker for %q, got %q", q, got)
		}
	}
	// A param merely ending in "Token" must not be mangled, and normal params
	// are preserved.
	got := redactTraceQuery("Action=AssumeRole&prefix=photos/2026&MyToken=keepme")
	if !strings.Contains(got, "Action=AssumeRole") || !strings.Contains(got, "prefix=photos/2026") ||
		!strings.Contains(got, "MyToken=keepme") {
		t.Fatalf("ANBM-006: ordinary params altered: %q", got)
	}
}

// ANBM-002 (XFF): forwarding headers from untrusted peers must not override aws:SourceIp.
func TestANBMUntrustedXFFIgnoredInSourceIP(t *testing.T) {
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],` +
		`"Resource":["arn:aws:s3:::b/*"],"Condition":{"IpAddress":{"aws:SourceIp":"10.9.9.0/24"}}}]}`
	p, err := policy.ParseConfig(strings.NewReader(pol))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://x/b/o", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("X-Forwarded-For", "10.9.9.9")
	r.Header.Set("X-Real-IP", "10.9.9.9")
	if p.IsAllowed(policy.Args{
		AccountName: "u", Action: policy.GetObjectAction, BucketName: "b", ObjectName: "o",
		ConditionValues: getConditionValues(r, "", auth.Credentials{AccessKey: "u"}),
	}) {
		t.Fatal("ANBM-002: X-Forwarded-For from untrusted peer bypassed aws:SourceIp")
	}
}

// ANBM-003 (DefaultCredentials): non-CI startup must reject empty/default root credentials.
func TestANBMRefuseDefaultCredentialsOutsideCI(t *testing.T) {
	if _, err := resolveRootCredentials(auth.Credentials{}, false); err == nil {
		t.Fatal("ANBM-003: expected error when root credentials are missing outside CI")
	}
	cred, err := resolveRootCredentials(auth.Credentials{}, true)
	if err != nil || !cred.Equal(auth.DefaultCredentials) {
		t.Fatalf("expected DefaultCredentials in CI mode, got %+v, err=%v", cred, err)
	}
}

// ANBM-004 (CORS): wildcard '*' origin config must not advertise Allow-Credentials: true.
func TestANBMCORSWildcardDisablesCredentials(t *testing.T) {
	setCORS := func(origins []string) {
		globalAPIConfig.mu.Lock()
		globalAPIConfig.corsAllowOrigins = origins
		globalAPIConfig.mu.Unlock()
	}

	globalAPIConfig.mu.RLock()
	orig := globalAPIConfig.corsAllowOrigins
	globalAPIConfig.mu.RUnlock()
	defer setCORS(orig)

	h := corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	setCORS([]string{"*"})
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("ANBM-004: wildcard CORS must not set Allow-Credentials, got %q", got)
	}

	setCORS([]string{"https://console.example.com"})
	req2 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req2.Header.Set("Origin", "https://console.example.com")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected Allow-Credentials=true for explicit origin, got %q", got)
	}
}

// ANBM-001 (SiteReplicationNetPerf/DevNull): unauthenticated requests must be rejected.
func TestANBMSiteReplicationPerfRequiresAuth(t *testing.T) {
	api := adminAPIHandlers{}
	for _, fn := range []http.HandlerFunc{api.SiteReplicationDevNull, api.SiteReplicationNetPerf} {
		req := httptest.NewRequest(http.MethodPost, "http://x/minio/admin/v3/site-replication/netperf", nil)
		req = req.WithContext(newContext(req, httptest.NewRecorder(), "test"))
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
			t.Fatalf("ANBM-001: unauthenticated site-replication perf request was not rejected (status %d)", rec.Code)
		}
	}
}
