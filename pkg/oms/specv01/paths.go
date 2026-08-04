/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package specv01

import "net/url"

const (
	PathHealth       = "/health"
	PathCapabilities = "/capabilities"
	PathStores       = "/v1/stores"
)

func StorePath(name string) string {
	return PathStores + "/" + url.PathEscape(name)
}

func MemoriesPath(storeName string) string {
	return StorePath(storeName) + "/memories"
}

func MemoryPath(storeName, memoryID string) string {
	return MemoriesPath(storeName) + "/" + url.PathEscape(memoryID)
}

func SearchPath(storeName string) string {
	return StorePath(storeName) + "/search"
}
