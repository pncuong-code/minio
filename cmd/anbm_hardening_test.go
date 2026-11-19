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
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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

	for _, wc := range [][]string{{"*"}, {"https://*"}, {"http://*"}} {
		setCORS(wc)
		req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("ANBM-004: wildcard CORS %v must not set Allow-Credentials, got %q", wc, got)
		}
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

// ANBM-023: a forged (unsigned) continuation-token must not inject a
// path-traversal metacache id, which would let the cache writer/cleaner escape
// the .metacache dir (e.g. recursively delete .minio.sys/config).
func TestANBMMetacacheIDRejectsTraversal(t *testing.T) {
	if valid := mustGetUUID(); !isValidMetacacheUUID(valid) {
		t.Fatalf("ANBM-023: rejected a real UUID %q", valid)
	}
	for _, bad := range []string{
		"../../../config", "..", "a/b", "../config", "",
		"deadbeef", strings.Repeat("g", 36), "aaaaaaaa-aaaa-aaaa-aaaa-aaaa/aaaaaaa",
	} {
		if isValidMetacacheUUID(bad) {
			t.Fatalf("ANBM-023: accepted invalid metacache id %q", bad)
		}
	}
	o := listPathOptions{Marker: "listing/key[minio_cache:v2,return:,id:../../../config,p:0,s:0]"}
	o.parseMarker()
	if strings.Contains(o.ID, "/") || strings.Contains(o.ID, "..") || !isValidMetacacheUUID(o.ID) {
		t.Fatalf("ANBM-023: parseMarker kept a forged id: %q", o.ID)
	}
}

// ANBM-025: legacy SigV2 presigned material must be redacted from traces too.
func TestANBMSigV2CredentialRedaction(t *testing.T) {
	q := "Action=ListObjects&AWSAccessKeyId=AKIAEXAMPLE123&Signature=abc123def456%3D&Expires=1700000000"
	got := redactTraceQuery(q)
	if strings.Contains(got, "AKIAEXAMPLE123") || strings.Contains(got, "abc123def456") {
		t.Fatalf("ANBM-025: SigV2 material leaked through trace: %q", got)
	}
	if !strings.Contains(got, "*REDACTED*") || !strings.Contains(got, "Expires=1700000000") {
		t.Fatalf("ANBM-025: unexpected trace redaction output: %q", got)
	}
}

// ANBM-V4-030: a forged multipart uploadID must not traverse out of the
// multipart directory when it becomes a filesystem path component.
func TestANBMUploadIDRejectsTraversal(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	legit := enc("deploymentid." + mustGetUUID() + "x123456789")
	if _, ok := uploadIDComponent(legit); !ok {
		t.Fatalf("ANBM-V4-030: rejected a legit uploadID")
	}
	for _, bad := range []string{
		enc("x./../../../victimbucket/victimobj"),
		enc("dep.../../config"),
		enc("dep." + "a/b"),
		enc("dep..."), // component ".."
	} {
		if _, ok := uploadIDComponent(bad); ok {
			t.Fatalf("ANBM-V4-030: accepted a traversing uploadID %q", bad)
		}
		if err := checkMultipartObjectArgs(context.Background(), "bucket", "obj", bad); err == nil {
			t.Fatalf("ANBM-V4-030: checkMultipartObjectArgs allowed %q", bad)
		}
	}
	for _, s := range []string{"..", "a/b", "a\\b", "..config", "../x"} {
		if isSafePathComponent(s) {
			t.Fatalf("ANBM-V4-030: isSafePathComponent accepted traversal %q", s)
		}
	}
}

// ANBM-V4-031: a presigned V2 request with a duplicate AWSAccessKeyId must be
// rejected, so the verified identity cannot differ from the authorized one.
func TestANBMSigV2DuplicateAccessKeyRejected(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet,
		"/b/o?AWSAccessKeyId=victim&AWSAccessKeyId=attacker&Expires=9999999999&Signature=c2ln", nil)
	if code := doesPresignV2SignatureMatch(r); code != ErrInvalidQueryParams {
		t.Fatalf("ANBM-V4-031: duplicate AWSAccessKeyId not rejected, got %v", code)
	}
}

// ANBM-V4-033: response-* overrides must be ignored on anonymous requests and
// honored on signed ones.
func TestANBMResponseOverrideOnlyWhenSigned(t *testing.T) {
	anon := httptest.NewRequest(http.MethodGet, "/b/o?response-content-type=text/html", nil)
	wa := httptest.NewRecorder()
	setHeadGetRespHeaders(wa, anon)
	if got := wa.Header().Get(xhttp.ContentType); got != "" {
		t.Fatalf("ANBM-V4-033: anonymous response-content-type honored: %q", got)
	}
	signed := httptest.NewRequest(http.MethodGet, "/b/o?response-content-type=text/html", nil)
	signed.Header.Set(xhttp.Authorization, signV4Algorithm+" Credential=a/b/c/s3/aws4_request, SignedHeaders=host, Signature=deadbeef")
	ws := httptest.NewRecorder()
	setHeadGetRespHeaders(ws, signed)
	if got := ws.Header().Get(xhttp.ContentType); got != "text/html" {
		t.Fatalf("ANBM-V4-033: signed response-content-type not honored: %q", got)
	}
}

// ANBM-V5-040: a batch job ID that escapes the batch-jobs prefix (path
// traversal) must be rejected before it is joined into an object path, while
// every server-generated ID is accepted.
func TestANBMBatchJobIDRejectsTraversal(t *testing.T) {
	for _, ok := range []string{
		"replicate-abc123:0",
		"keyrotate-abc123:1",
		"expire-aBc9:-1", // single-node proxy index is -1
	} {
		if err := validateBatchJobID(ok); err != nil {
			t.Fatalf("ANBM-V5-040: rejected a legit job ID %q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"../config/iam",
		"replicate-../config",
		"expire-a:0/../../buckets",
		"replicate-a\\b:0",
		"evil-abc:0",         // unknown job type
		"replicate-ab!cd:0",  // non-alnum uuid
		"replicate-abc:",     // missing index
		"replicate-abc",      // missing separator+index
		"../buckets",
	} {
		if err := validateBatchJobID(bad); err == nil {
			t.Fatalf("ANBM-V5-040: accepted an unsafe job ID %q", bad)
		}
	}
}

// ANBM-V5-041: a batch job must not accept a reserved/meta bucket as source or
// target, so it cannot read or overwrite .minio.sys (IAM/config).
func TestANBMBatchJobRejectsReservedBucket(t *testing.T) {
	for _, bad := range []string{"", minioMetaBucket, minioMetaBucket + "/config", minioReservedBucket} {
		if err := batchValidateBucket(bad); err == nil {
			t.Fatalf("ANBM-V5-041: accepted reserved/meta bucket %q", bad)
		}
	}
	if err := batchValidateBucket("user-bucket"); err != nil {
		t.Fatalf("ANBM-V5-041: rejected a normal bucket: %v", err)
	}
}

// ANBM-V5-046: the LDAP STS rate-limiter must bound both the size of each map
// key and the number of entries, so an anonymous caller cannot amplify a large
// form field into unbounded heap.
func TestANBMSTSLimiterKeyAndEntriesBounded(t *testing.T) {
	if got := boundLimiterKey("short"); got != "short" {
		t.Fatalf("ANBM-V5-046: short key altered: %q", got)
	}
	big := strings.Repeat("a", 10<<20)
	if got := boundLimiterKey(big); len(got) > stsLDAPLoginMaxKeyLen {
		t.Fatalf("ANBM-V5-046: oversized key not bounded: len=%d", len(got))
	}
	if boundLimiterKey(strings.Repeat("a", 1<<16)) == boundLimiterKey(strings.Repeat("b", 1<<16)) {
		t.Fatalf("ANBM-V5-046: distinct oversized keys collapsed to one key")
	}

	set := newSTSLDAPLoginKeyLimiterSet(time.Minute, stsLDAPLoginBurst, stsLDAPLoginEntryTTL)
	now := UTCNow()
	for i := 0; i < stsLDAPLoginMaxEntries+500; i++ {
		set.Allow(now, "user-"+strconv.Itoa(i))
	}
	set.mu.Lock()
	n := len(set.entries)
	set.mu.Unlock()
	if n > stsLDAPLoginMaxEntries {
		t.Fatalf("ANBM-V5-046: limiter map grew past cap: %d > %d", n, stsLDAPLoginMaxEntries)
	}
}

// ANBM-V5-053: describe-job must redact every secret in a job definition
// (source and target credentials, notification tokens, key-rotation key).
func TestANBMBatchJobRedactsAllSecrets(t *testing.T) {
	r := &BatchJobReplicateV1{}
	r.Source.Creds.SecretKey = "src-secret"
	r.Source.Creds.SessionToken = "src-token"
	r.Target.Creds.SecretKey = "tgt-secret"
	r.Flags.Notify.Token = "notify-token"
	r.RedactSensitive()
	for _, got := range []string{r.Source.Creds.SecretKey, r.Source.Creds.SessionToken, r.Target.Creds.SecretKey, r.Flags.Notify.Token} {
		if got != redactedText {
			t.Fatalf("ANBM-V5-053: replicate secret not redacted: %q", got)
		}
	}

	kr := &BatchJobKeyRotateV1{}
	kr.Encryption.Key = "sse-c-key"
	kr.Flags.Notify.Token = "kr-token"
	kr.RedactSensitive()
	if kr.Encryption.Key != redactedText || kr.Flags.Notify.Token != redactedText {
		t.Fatalf("ANBM-V5-053: keyrotate secret not redacted")
	}
}
