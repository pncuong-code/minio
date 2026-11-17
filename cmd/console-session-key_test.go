// Copyright (c) 2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cmd

import (
	"testing"

	"github.com/minio/minio/internal/auth"
)

// CVE-2026-113466: the Console session key must not be derivable from the
// (public) deployment ID alone.
func TestConsoleSessionPassphraseNotDeploymentID(t *testing.T) {
	saved := globalActiveCred
	defer func() { globalActiveCred = saved }()

	globalActiveCred = auth.Credentials{AccessKey: "minioadmin", SecretKey: "secret-one-1234567890"}
	p1 := consoleSessionPassphrase()
	if p1 == globalDeploymentID() {
		t.Fatal("console passphrase equals the deployment ID")
	}
	if p1 != consoleSessionPassphrase() {
		t.Fatal("console passphrase is not deterministic across calls/nodes")
	}

	globalActiveCred = auth.Credentials{AccessKey: "minioadmin", SecretKey: "secret-two-1234567890"}
	if p2 := consoleSessionPassphrase(); p2 == p1 {
		t.Fatal("console passphrase does not depend on the root secret")
	}
}
