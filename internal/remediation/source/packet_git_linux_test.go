//go:build linux

package source

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketTreeAndBlobHashesMatchRealGit(t *testing.T) {
	for _, identityLength := range []int{40, 64} {
		t.Run(fmt.Sprint(identityLength), func(t *testing.T) {
			format := "sha1"
			if identityLength == 64 {
				format = "sha256"
			}
			repository := t.TempDir()
			fixtureGit(t, repository, nil, "init", "--quiet", "--object-format="+format, "--initial-branch=main", "--template=")
			writeFixture(t, filepath.Join(repository, "a", "b"), "nested\n", 0600)
			writeFixture(t, filepath.Join(repository, "a.c"), "file sorts before the a/ tree\n", 0600)
			writeFixture(t, filepath.Join(repository, "run"), "#!/bin/sh\nexit 0\n", 0700)
			fixtureGit(t, repository, nil, "add", ".")
			fixtureGit(t, repository, nil, "commit", "--quiet", "-m", "synthetic packet source")
			target := targetAtHEAD(t, repository)
			fixture := newPacketFixture(t, identityLength,
				packetNode{name: "run", mode: "100755", content: []byte("#!/bin/sh\nexit 0\n")},
				packetNode{name: "a", mode: "040000", children: []packetNode{{name: "b", content: []byte("nested\n")}}},
				packetNode{name: "a.c", content: []byte("file sorts before the a/ tree\n")},
			)
			require.Equal(t, target.Tree, fixture.target.Tree, "independent fixture encoding must match Git tree ordering and raw identities")
			api := newAPIFixture(t, fixture.replies)
			packet, err := api.client.Packet(t.Context(), fixture.target, []string{"a/b", "a.c", "run"})
			require.NoError(t, err)
			for _, file := range packet.Files {
				expected := strings.TrimSpace(string(fixtureGit(t, repository, []byte(file.Content), "hash-object", "--stdin")))
				require.Equal(t, expected, file.BlobSHA)
				require.Equal(t, file.Content, string(fixtureGit(t, repository, nil, "cat-file", "blob", file.BlobSHA)))
			}
		})
	}
}
