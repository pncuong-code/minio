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
}
