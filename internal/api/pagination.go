/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"context"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

// listPage serves one page of a limited Kubernetes list.
//
// controller-runtime's cache reader truncates a limited List at opts.Limit and
// stamps the "continue-not-supported" sentinel, so it can never resume: paging
// through the cache silently drops every item past the first page. Limited
// lists therefore go to the uncached API reader, whose continue tokens are
// real. When no uncached reader is configured (unit tests build Handlers
// without one) the cached client is asked for the complete, unlimited list and
// the whole result is returned as a single page with no continue token; a
// continue token supplied in that mode cannot have been issued by this server
// and is rejected. Unlimited lists (Limit == 0) always use the cached client.
//
// The returned error is already a *fiber.Error carrying the client-facing
// status; what names the listed resource in the failure message.
func (h *Handlers) listPage(ctx context.Context, list client.ObjectList, opts *client.ListOptions, what string) error {
	if opts == nil {
		opts = &client.ListOptions{}
	}
	switch {
	case opts.Limit <= 0:
		if err := h.client.List(ctx, list, opts); err != nil {
			return listPageError(what, err)
		}
	case h.apiReader != nil:
		if err := h.apiReader.List(ctx, list, opts); err != nil {
			return listPageError(what, err)
		}
	default:
		if opts.Continue != "" {
			return fiber.NewError(fiber.StatusBadRequest, "continue is not supported: list pagination requires an uncached API reader")
		}
		unlimited := *opts
		unlimited.Limit = 0
		unlimited.Continue = ""
		if err := h.client.List(ctx, list, &unlimited); err != nil {
			return listPageError(what, err)
		}
		list.SetContinue("")
		list.SetRemainingItemCount(nil)
	}
	// Defense in depth: the sentinel must never reach a client even if a
	// cache-backed reader served the page.
	list.SetContinue(NormalizeListContinue(list.GetContinue()))
	// Every caller applies per-item authorization after paging, so the API
	// server's collection-wide remaining count would reveal how many objects
	// the caller is not allowed to see on later pages. Clients page with the
	// continue token; the optional count is never forwarded.
	list.SetRemainingItemCount(nil)
	return nil
}

func listPageError(what string, err error) error {
	return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("failed to list %s: %v", what, err))
}

// maxAuthorizedListPages bounds how many Kubernetes pages one filtered list
// request may walk while filling a page with authorized items.
const maxAuthorizedListPages = 20

// collectAuthorizedPages walks Kubernetes pages until the post-authorization
// result holds at least limit items, the collection is exhausted, or the page
// budget is spent, and returns the items with the continuation cursor of the
// last page read. Filtering a single raw page would otherwise hand a scoped
// caller one cursor per Kubernetes page — including pages the filter emptied
// — and let it count and order objects it is not allowed to list. A page may
// overfill by up to one Kubernetes page; items are never trimmed because the
// cursor has already moved past them.
func collectAuthorizedPages[T any](limit int64, start string, fetch func(continueToken string) ([]T, string, error)) ([]T, string, error) {
	if limit <= 0 {
		// An unlimited request is served as one complete page.
		return fetch(start)
	}
	items := []T{}
	continueToken := start
	for page := 1; ; page++ {
		pageItems, next, err := fetch(continueToken)
		if err != nil {
			return nil, "", err
		}
		items = append(items, pageItems...)
		continueToken = next
		if next == "" || (limit > 0 && int64(len(items)) >= limit) || page >= maxAuthorizedListPages {
			return items, continueToken, nil
		}
	}
}
