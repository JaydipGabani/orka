//go:build patchverify_fixture

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

func allowed(quantity int) bool {
	return true
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(125)
	}
	quantity, err := strconv.Atoi(os.Args[1])
	if err != nil {
		os.Exit(125)
	}
	if !allowed(quantity) {
		fmt.Println("rejected")
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:18080/reserve")
	if err != nil {
		os.Exit(125)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 64))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(content) != "reserved\n" {
		os.Exit(125)
	}
	fmt.Println("accepted")
}
