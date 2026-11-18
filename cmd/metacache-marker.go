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

package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// markerTagVersion is the marker version.
// Should not need to be updated unless a fundamental change is made to the marker format.
const markerTagVersion = "v2"

// isValidMetacacheUUID reports whether id has the canonical UUID shape produced
// by mustGetUUID (8-4-4-4-12 hex). ANBM-023: metacache ids are always UUIDs
// internally; rejecting anything else stops path-component injection through the
// client-supplied continuation-token.
func isValidMetacacheUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		case c == '-' && (i == 8 || i == 13 || i == 18 || i == 23):
		default:
			return false
		}
	}
	return true
}

// parseMarker will parse a marker possibly encoded with encodeMarker
func (o *listPathOptions) parseMarker() {
	s := o.Marker
	if !strings.Contains(s, "[minio_cache:"+markerTagVersion) {
		return
	}
	start := strings.LastIndex(s, "[")
	o.Marker = s[:start]
	end := strings.LastIndex(s, "]")
	tag := strings.Trim(s[start:end], "[]")
	tags := strings.SplitSeq(tag, ",")
	for tag := range tags {
		kv := strings.Split(tag, ":")
		if len(kv) < 2 {
			continue
		}
		switch kv[0] {
		case "minio_cache":
			if kv[1] != markerTagVersion {
				continue
			}
		case "id":
			// ANBM-023: o.ID becomes a path component via
			// metacachePrefixForID -> pathJoin, which cleans "..". The
			// continuation-token carrying this marker is only base64 (not
			// signed), so a client can forge id="../../../config" and make the
			// metacache writer/cleaner escape the cache dir (e.g. recursively
			// delete .minio.sys/config). Accept only canonical UUID ids;
			// anything else starts a fresh listing with a safe id.
			if isValidMetacacheUUID(kv[1]) {
				o.ID = kv[1]
			} else {
				o.ID = mustGetUUID()
				o.Create = true
			}
		case "return":
			o.ID = mustGetUUID()
			o.Create = true
		case "p": // pool
			v, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				o.ID = mustGetUUID()
				o.Create = true
				continue
			}
			o.pool = int(v)
		case "s": // set
			v, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				o.ID = mustGetUUID()
				o.Create = true
				continue
			}
			o.set = int(v)
		default:
			// Ignore unknown
		}
	}
}

// encodeMarker will encode a uuid and return it as a marker.
// uuid cannot contain '[', ':' or ','.
func (o listPathOptions) encodeMarker(marker string) string {
	if o.ID == "" {
		// Mark as returning listing...
		return fmt.Sprintf("%s[minio_cache:%s,return:]", marker, markerTagVersion)
	}
	if strings.ContainsAny(o.ID, "[:,") {
		internalLogIf(context.Background(), fmt.Errorf("encodeMarker: uuid %s contained invalid characters", o.ID))
	}
	return fmt.Sprintf("%s[minio_cache:%s,id:%s,p:%d,s:%d]", marker, markerTagVersion, o.ID, o.pool, o.set)
}
