//go:build linux

package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStrictProfileJSON(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	raw, err := json.Marshal(input.profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProfile(raw); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"duplicate":      bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"colliding":      bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		"unknown":        append([]byte(`{"unapproved":"SYNTHETIC_PRIVATE_MARKER",`), raw[1:]...),
		"null":           bytes.Replace(raw, []byte(`"gaps":[]`), []byte(`"gaps":null`), 1),
		"extra-document": append(bytes.Clone(raw), []byte("{}")...),
		"array":          []byte("[]"),
		"malformed":      []byte(`{"private":"SYNTHETIC_PRIVATE_MARKER"`),
		"invalid-utf8":   {0xff},
		"new-version":    bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1),
		"null-nested":    bytes.Replace(raw, []byte(`"driver":{`), []byte(`"driver":null,"unused":{`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProfile(data); err == nil || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") {
				t.Fatal("non-strict profile was accepted or input content escaped through an error")
			}
		})
	}
	for _, size := range []int{MaxProfileBytes - 1, MaxProfileBytes, MaxProfileBytes + 1} {
		t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
			padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), size-len(raw))...)
			_, err := ParseProfile(padded)
			if size > MaxProfileBytes {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatal("profile byte limit was not enforced")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProfileAndChecksDigestContract(t *testing.T) {
	t.Parallel()
	checks := []Check{{ID: "repro", Class: Reproduction}, {ID: "normal", Class: Normal}}
	got, err := DigestChecks(checks)
	if err != nil {
		t.Fatal(err)
	}
	want := testDigest([]byte(`[{"id":"normal","class":"normal"},{"id":"repro","class":"reproduction"}]`))
	if got != want || checks[0].ID != "repro" {
		t.Fatal("canonical check digest encoding or caller order changed")
	}
	for _, invalid := range [][]Check{
		nil,
		{{ID: "normal", Class: Normal}},
		{{ID: "repro", Class: Reproduction}, {ID: "repro", Class: Normal}},
		{{ID: "repro", Class: Reproduction}, {ID: "normal", Class: "unknown"}},
		{{ID: "../repro", Class: Reproduction}, {ID: "normal", Class: Normal}},
	} {
		if _, err := DigestChecks(invalid); err == nil {
			t.Fatal("an incomplete or ambiguous check manifest was accepted")
		}
	}
	input := newFixture(t, "ok")
	approved, err := DigestProfile(input.profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(input.profile, input.root, ""); !errors.Is(err, ErrApproval) {
		t.Fatal("driver execution can be authorized without an explicit approved digest")
	}
	originalScope := input.profile.Scope[0]
	bridge := input.bridge(t)
	input.profile.Scope[0] = "changed"
	if bridge.profile.Scope[0] != originalScope {
		t.Fatal("caller mutation changed an approved profile")
	}
	if _, err := New(input.profile, input.root, approved); !errors.Is(err, ErrApproval) {
		t.Fatal("approval survived changed profile scope")
	}
}

func TestProfileRejectsUnpinnedOrUnsafeInputs(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Profile){
		"tag-original": func(profile *Profile) { profile.OriginalImage = "example.invalid/controller:latest" },
		"tag-control":  func(profile *Profile) { profile.ControlImage = "example.invalid/controller:1.0" },
		"short-commit": func(profile *Profile) { profile.Commit = "deadbeef" },
		"upper-commit": func(profile *Profile) { profile.Commit = strings.Repeat("A", 40) },
		"http-repo":    func(profile *Profile) { profile.Repository = "http://example.invalid/public/repo" },
		"local-repo":   func(profile *Profile) { profile.Repository = "https://127.0.0.1/repo" },
		"repo-userinfo": func(profile *Profile) {
			profile.Repository = "https://user:SYNTHETIC_PRIVATE_MARKER@example.invalid/repo"
		},
		"repo-query":     func(profile *Profile) { profile.Repository += "?token=SYNTHETIC_PRIVATE_MARKER" },
		"relative-file":  func(profile *Profile) { profile.Driver.Path = "driver" },
		"unclean-file":   func(profile *Profile) { profile.Configuration.Path += "/../file" },
		"same-files":     func(profile *Profile) { profile.Driver.Path = profile.Configuration.Path },
		"missing-scope":  func(profile *Profile) { profile.Scope = nil },
		"null-gaps":      func(profile *Profile) { profile.Gaps = nil },
		"scope-control":  func(profile *Profile) { profile.Scope = []string{"scope\nforged"} },
		"wrong-platform": func(profile *Profile) { profile.Platform = "../platform" },
		"wrong-checks":   func(profile *Profile) { profile.ChecksDigest = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			input := newFixture(t, "ok")
			mutate(&input.profile)
			if _, err := DigestProfile(input.profile); !errors.Is(err, ErrInvalidProfile) {
				t.Fatal("unsafe profile input was accepted")
			}
		})
	}
}

func TestFilesystemSafety(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*testing.T, *fixture){
		"driver-group-write": func(t *testing.T, input *fixture) { changeMode(t, input.profile.Driver.Path, 0770) },
		"driver-world-write": func(t *testing.T, input *fixture) { changeMode(t, input.profile.Driver.Path, 0702) },
		"driver-not-executable": func(t *testing.T, input *fixture) {
			changeMode(t, input.profile.Driver.Path, 0600)
		},
		"config-public-read": func(t *testing.T, input *fixture) {
			changeMode(t, input.profile.Configuration.Path, 0644)
		},
		"config-group-write": func(t *testing.T, input *fixture) {
			changeMode(t, input.profile.Configuration.Path, 0620)
		},
		"config-executable": func(t *testing.T, input *fixture) {
			changeMode(t, input.profile.Configuration.Path, 0700)
		},
		"root-public": func(t *testing.T, input *fixture) { changeMode(t, input.root, 0755) },
		"driver-link": func(t *testing.T, input *fixture) {
			linked := input.profile.Driver.Path + "-link"
			if err := os.Symlink(input.profile.Driver.Path, linked); err != nil {
				t.Fatal(err)
			}
			input.profile.Driver.Path = linked
		},
		"config-link": func(t *testing.T, input *fixture) {
			linked := input.profile.Configuration.Path + "-link"
			if err := os.Symlink(input.profile.Configuration.Path, linked); err != nil {
				t.Fatal(err)
			}
			input.profile.Configuration.Path = linked
		},
		"ancestor-link": func(t *testing.T, input *fixture) {
			linked := filepath.Join(filepath.Dir(input.root), "parent-link")
			if err := os.Symlink(filepath.Dir(input.profile.Configuration.Path), linked); err != nil {
				t.Fatal(err)
			}
			input.profile.Configuration.Path = filepath.Join(linked, "private-config")
		},
		"root-link": func(t *testing.T, input *fixture) {
			linked := input.root + "-link"
			if err := os.Symlink(input.root, linked); err != nil {
				t.Fatal(err)
			}
			input.root = linked
		},
		"config-directory": func(_ *testing.T, input *fixture) {
			input.profile.Configuration.Path = input.root
		},
		"config-fifo": func(t *testing.T, input *fixture) {
			fifo := filepath.Join(filepath.Dir(input.root), "config-fifo")
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			input.profile.Configuration.Path = fifo
		},
		"config-hardlink": func(t *testing.T, input *fixture) {
			if err := os.Link(input.profile.Configuration.Path, input.profile.Configuration.Path+"-hardlink"); err != nil {
				t.Fatal(err)
			}
		},
		"writable-ancestor": func(t *testing.T, input *fixture) {
			changeMode(t, filepath.Dir(input.root), 0777)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input := newFixture(t, "ok")
			mutate(t, &input)
			approval, err := DigestProfile(input.profile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(input.profile, input.root, approval); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("unsafe file or path was not rejected: %v", err)
			}
		})
	}
}

func changeMode(t *testing.T, name string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func TestChangedApprovedFilesAndRootAreRejected(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"driver", "configuration", "root"} {
		t.Run(target, func(t *testing.T) {
			input := newFixture(t, "ok")
			bridge := input.bridge(t)
			switch target {
			case "driver":
				writeFixture(t, input.profile.Driver.Path, []byte("#!/bin/sh\nexit 0\n"), 0700)
			case "configuration":
				writeFixture(t, input.profile.Configuration.Path, []byte("different"), 0600)
			case "root":
				if err := os.Rename(input.root, input.root+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(input.root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := bridge.Baseline(context.Background(), "not-started"); err == nil {
				t.Fatal("mutated approved input or replaced private root was accepted")
			}
			if _, err := os.Stat(filepath.Join(input.root, "not-started")); !os.IsNotExist(err) {
				t.Fatal("mutated approved input started execution")
			}
		})
	}
}

func TestInputFileByteBounds(t *testing.T) {
	// Sequential to keep the 64 MiB executable boundary probe memory-bounded.
	for _, test := range []struct {
		name       string
		limit      int
		executable bool
	}{
		{"driver", MaxDriverBytes, true},
		{"configuration", MaxConfigurationBytes, false},
		{"patch", MaxPatchBytes, false},
	} {
		for _, size := range []int{test.limit - 1, test.limit, test.limit + 1} {
			t.Run(fmt.Sprintf("%s-%d", test.name, size), func(t *testing.T) {
				directory := t.TempDir()
				changeMode(t, directory, 0700)
				path := filepath.Join(directory, "bounded-input")
				mode := os.FileMode(0600)
				if test.executable {
					mode = 0700
				}
				file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(int64(size)); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				hash := sha256.New()
				if _, err := io.Copy(hash, file); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				identity := FileIdentity{Path: path, Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}
				data, err := readApproved(identity, test.limit, test.executable)
				if size > test.limit {
					if !errors.Is(err, ErrTooLarge) {
						t.Fatal("input exceeded its exact byte limit")
					}
				} else if err != nil || len(data) != size {
					t.Fatalf("input below or at the byte limit was rejected: %v", err)
				}
			})
		}
	}
}

func TestCheckCountBounds(t *testing.T) {
	t.Parallel()
	for _, count := range []int{MaxChecks - 1, MaxChecks, MaxChecks + 1} {
		checks := make([]Check, count)
		for index := range checks {
			checks[index] = Check{ID: fmt.Sprintf("check-%03d", index), Class: Normal}
		}
		checks[0].Class = Reproduction
		_, err := DigestChecks(checks)
		if count > MaxChecks {
			if err == nil {
				t.Fatal("too many checks were accepted")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzParseProfile(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"version":2}`))
	f.Add([]byte(`{"scope":[null]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxProfileBytes+1 {
			return
		}
		profile, err := ParseProfile(data)
		if err == nil {
			if _, err := DigestProfile(profile); err != nil {
				t.Fatal("accepted profile is not digestible")
			}
		}
	})
}
