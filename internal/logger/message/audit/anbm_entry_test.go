// Copyright (c) 2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ANBM-014: presigned / STS credentials carried in the request query must be
// redacted from audit entries, which are shipped to external sinks (webhook,
// Kafka) whose readers are not MinIO principals.
func TestANBMAuditQueryRedaction(t *testing.T) {
	target := "http://x/b/o?X-Amz-Security-Token=FwoGsession&X-Amz-Signature=deadbeef" +
		"&X-Amz-Credential=AKIA%2F20260101&WebIdentityToken=jwt.value&prefix=keep"
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	entry := ToEntry(w, r, nil, "dep")

	for _, k := range []string{
		"X-Amz-Security-Token", "X-Amz-Signature", "X-Amz-Credential", "WebIdentityToken",
	} {
		if got := entry.ReqQuery[k]; got != "*REDACTED*" {
			t.Fatalf("ANBM-014: query %q not redacted, got %q", k, got)
		}
	}
	if entry.ReqQuery["prefix"] != "keep" {
		t.Fatalf("ANBM-014: ordinary query param was altered: %q", entry.ReqQuery["prefix"])
	}
}
