/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"fmt"
	"strconv"
)

const (
	// DefaultLimit is the default number of items per page
	DefaultLimit = 100

	// MaxLimit is the maximum number of items per page
	MaxLimit = 500

	// cacheContinueUnsupported is the sentinel controller-runtime's cache
	// reader stamps on every limited List it serves. The cache cannot resume a
	// list from it, so it must never be echoed to API clients as a usable
	// continue token nor handed back to the cache on the next request.
	cacheContinueUnsupported = "continue-not-supported"
)

// Pagination holds pagination parameters
type Pagination struct {
	Limit    int64
	Continue string
}

// ParsePagination parses pagination parameters from query strings
func ParsePagination(limitStr, continueToken string) (*Pagination, error) {
	p := &Pagination{
		Limit:    DefaultLimit,
		Continue: NormalizeListContinue(continueToken),
	}

	if limitStr != "" {
		limit, err := strconv.ParseInt(limitStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid limit parameter: %w", err)
		}
		if limit < 1 {
			return nil, fmt.Errorf("limit must be at least 1")
		}
		if limit > MaxLimit {
			limit = MaxLimit
		}
		p.Limit = limit
	}

	return p, nil
}

// NormalizeListContinue strips the controller-runtime cache sentinel from a
// list continue token. Cache-backed lists report "continue-not-supported"
// whenever a limit was applied; clients that follow it verbatim would
// otherwise receive a 500 from the cache on the next page.
func NormalizeListContinue(token string) string {
	if token == cacheContinueUnsupported {
		return ""
	}
	return token
}
