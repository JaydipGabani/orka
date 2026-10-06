package disclosure

import (
	"errors"
	"testing"
)

func TestOutgoingContentCannotUseBaselinePresenceAsPermission(t *testing.T) {
	for _, domain := range []Domain{Model, Candidate, Artifact} {
		for _, content := range []string{
			`{"password":"example-value"}`,
			"diff --git a/config.txt b/config.txt\n--- a/config.txt\n+++ b/config.txt\n@@ -1 +1 @@\n-password=private-value\n+enabled=true\n",
			"api_key=private-value",
		} {
			if err := Check(domain, []byte(content)); !errors.Is(err, ErrBlocked) {
				t.Fatal("credential-shaped outgoing bytes were accepted", domain)
			}
		}
	}
}

func TestOrdinaryCodeAndSchemaRemainUsable(t *testing.T) {
	for _, content := range []string{
		`{"password":{"type":"string"}}`,
		"package demo\nfunc options(info Config){ _ = Options{Password: info.Password} }\n",
		"diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-allowed=true\n+allowed=false\n",
	} {
		if err := Check(Candidate, []byte(content)); err != nil {
			t.Fatal("ordinary source/reference data rejected", err)
		}
	}
}
