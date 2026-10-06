package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	materializeTimeout  = 3 * time.Minute
	gitTimeout          = 60 * time.Second
	gitMaxFileBytes     = 128 << 20
	maxDiskBytes        = 256 << 20
	maxCheckoutBytes    = 128 << 20
	maxTreeEntries      = 8192
	maxTreeListingBytes = 2 << 20
	maxPathBytes        = 1024
	maxPathDepth        = 32
	diskCheckInterval   = 100 * time.Millisecond
)

var errSourceLimit = errors.New("public source exceeds materialization resource limits")

type commandRunner func(*exec.Cmd) error

// Materialize rechecks public visibility and the exact commit/tree through the
// anonymous GitHub API, then fetches only that commit into a detached Git worktree.
// destination must be an absolute path with an existing, symlink-free parent
// outside Git worktrees. A new checkout is private (0700) and carries a snapshot
// marker. An existing checkout is accepted only after read-only verification of
// that marker, public origin, exact objects, index, and unchanged working tree.
// Unmarked directories and modified checkouts are never adopted or overwritten.
//
// Linux, trusted system Git, and util-linux /usr/bin/prlimit are required. Git
// processes have 60-second wall, 30-second CPU, 512-MiB address-space, and 128-MiB
// per-file limits. The whole operation has a 3-minute deadline. A 256-MiB disk
// watchdog samples every 100ms; it is not a filesystem quota and can transiently
// overshoot. Checkout is preflighted to at most 8192 entries and 128 MiB.
// Symlinks and gitlinks are refused, matching
// patchverification.PrepareSources; LFS files remain uninterpreted pointers.
// No hooks, external filters, submodule commands, credential helpers, or source code run.
func Materialize(ctx context.Context, target Target, destination string) error {
	return materialize(ctx, target, destination, Client{}, (*exec.Cmd).Run)
}

func materialize(ctx context.Context, target Target, destination string, client Client, run commandRunner) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	parent, err := destinationLocation(destination)
	if err != nil {
		return err
	}
	binary, err := trustedGit()
	if err != nil {
		return err
	}
	operation, cancel := context.WithTimeout(ctx, materializeTimeout)
	defer cancel()

	if _, err := os.Lstat(destination); err == nil {
		return resumeMaterialized(operation, target, destination, parent, binary, client, run)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect source destination: %w", err)
	}
	if err := revalidatePublic(operation, client, target); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".orka-public-source-")
	if err != nil {
		return fmt.Errorf("create private source staging directory: %w", err)
	}
	info, err := os.Lstat(staging)
	if err != nil {
		return errors.Join(err, os.Remove(staging))
	}
	published := false
	defer func() {
		if !published {
			resultErr = errors.Join(resultErr, removeOwnedDirectory(staging, info))
		}
	}()
	if err := os.Chmod(staging, 0700); err != nil {
		return fmt.Errorf("restrict source staging permissions: %w", err)
	}
	guarded, stopGuard := guardDisk(operation, staging)
	defer stopGuard()
	git := sourceGit{root: staging, binary: binary, runCommand: run}
	if err := git.populate(guarded, target); err != nil {
		return err
	}
	if err := sealMaterialized(guarded, staging, target); err != nil {
		return err
	}
	if err := checkDisk(guarded, staging); err != nil {
		return err
	}
	if err := guarded.Err(); err != nil {
		return context.Cause(guarded)
	}
	if err := requireNewDestination(destination); err != nil {
		return err
	}
	// Publication must not replace a destination created while the fetch was
	// running. A check followed by os.Rename would overwrite an empty directory.
	if err := publishNoReplace(staging, destination); err != nil {
		return fmt.Errorf("publish source without replacing destination: %w", err)
	}
	published = true
	return nil
}

func revalidatePublic(operation context.Context, client Client, target Target) error {
	confirmed, err := client.Resolve(operation, target.Repository.URL, target.Commit)
	if err != nil {
		return fmt.Errorf("revalidate public source: %w", err)
	}
	if confirmed.Commit != target.Commit || confirmed.Tree != target.Tree {
		return errors.New("public source no longer matches the selected exact commit and tree")
	}
	return nil
}

func validateTarget(target Target) error {
	repository, err := parseRepositoryURL(target.Repository.URL)
	if err != nil {
		return err
	}
	if repository.URL != target.Repository.URL || repository.Owner != target.Repository.Owner ||
		repository.Name != target.Repository.Name || !validRef(target.Repository.DefaultBranch) ||
		!validRef(target.Ref) || !validObjectID(target.Commit) || !validObjectID(target.Tree) ||
		len(target.Commit) != len(target.Tree) || (validObjectID(target.Ref) && target.Ref != target.Commit) {
		return errors.New("source target must contain consistent repository metadata and exact commit/tree identities")
	}
	return nil
}

func requireNewDestination(destination string) error {
	if _, err := destinationLocation(destination); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("inspect source destination: %w", err)
		}
		return errors.New("source destination already exists; refusing overwrite")
	}
	return nil
}

func destinationLocation(destination string) (string, error) {
	if !filepath.IsAbs(destination) || destination == string(filepath.Separator) ||
		filepath.Clean(destination) != destination || len(destination) > 4096 ||
		!utf8.ValidString(destination) || strings.ContainsFunc(destination, unicode.IsControl) ||
		strings.ContainsAny(destination, `\:,?#`) || strings.EqualFold(strings.TrimRight(filepath.Base(destination), ". "), ".git") {
		return "", errors.New("source destination must be a canonical absolute new directory path")
	}
	parent := filepath.Dir(destination)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve source destination parent: %w", err)
	}
	if resolved != parent {
		return "", errors.New("source destination parent must not contain symlinks")
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect source destination parent: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("source destination parent is not a directory")
	}
	ancestorModes := make([]os.FileMode, 0, 16)
	for ancestor := parent; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Stat(ancestor)
		if err != nil {
			return "", fmt.Errorf("inspect source destination ancestor: %w", err)
		}
		ancestorModes = append(ancestorModes, info.Mode())
		if _, err := os.Lstat(filepath.Join(ancestor, ".git")); err == nil {
			return "", errors.New("source destination must be outside Git worktrees and repository metadata")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect source destination Git boundary: %w", err)
		}
		if _, err := os.Lstat(filepath.Join(ancestor, "HEAD")); err == nil {
			if _, err := os.Lstat(filepath.Join(ancestor, "objects")); err == nil {
				return "", errors.New("source destination must be outside Git worktrees and repository metadata")
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("inspect source destination Git boundary: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect source destination Git boundary: %w", err)
		}
		if filepath.Dir(ancestor) == ancestor {
			break
		}
	}
	if !safeAncestorModes(ancestorModes) {
		return "", errors.New("source destination has an exposed group/world-writable ancestor without the sticky bit")
	}
	return parent, nil
}

func safeAncestorModes(parentToRoot []os.FileMode) bool {
	for _, mode := range slices.Backward(parentToRoot) {
		if mode.Perm()&0022 != 0 && mode&os.ModeSticky == 0 {
			return false
		}
		// A private ancestor prevents access to even permissive descendants.
		// Still inspect its parents first: an exposed parent could replace it.
		if mode.Perm()&0077 == 0 {
			return true
		}
	}
	return true
}

func removeOwnedDirectory(directory string, expected os.FileInfo) error {
	actual, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned source staging for cleanup: %w", err)
	}
	if !actual.IsDir() || !os.SameFile(actual, expected) {
		return errors.New("source staging identity changed; refusing to remove an unowned path")
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove owned source staging: %w", err)
	}
	return nil
}

type sourceGit struct {
	root       string
	binary     string
	runCommand commandRunner
}

func (git *sourceGit) populate(ctx context.Context, target Target) error {
	if err := git.initialize(ctx, target); err != nil {
		return err
	}
	if _, err := git.run(ctx, 4096, "fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules",
		"--no-write-fetch-head", "--no-auto-maintenance", "--", target.Repository.URL+".git", target.Commit); err != nil {
		return err
	}
	return git.checkout(ctx, target)
}

const checkoutAttributes = "* -filter -text -eol -ident -working-tree-encoding\n"

func (git *sourceGit) initialize(ctx context.Context, target Target) error {
	format := "sha1"
	if len(target.Commit) == 64 {
		format = "sha256"
	}
	if _, err := git.run(ctx, 4096, "init", "--quiet", "--template=", "--object-format="+format, "--", git.root); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(git.root, ".git", "config"), []byte(checkoutConfig(target)), 0600); err != nil {
		return fmt.Errorf("write canonical public source configuration: %w", err)
	}
	if err := os.Mkdir(filepath.Join(git.root, ".git", "tmp"), 0700); err != nil {
		return fmt.Errorf("create private Git temporary directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(git.root, ".git", "info"), 0700); err != nil {
		return fmt.Errorf("create private Git attributes directory: %w", err)
	}
	// Repository attributes must not transform source bytes or select external
	// filters during checkout. info/attributes has the highest precedence.
	if err := os.WriteFile(filepath.Join(git.root, ".git", "info", "attributes"), []byte(checkoutAttributes), 0600); err != nil {
		return fmt.Errorf("disable source checkout transformations: %w", err)
	}
	return nil
}

func checkoutConfig(target Target) string {
	version, extensions := "0", ""
	if len(target.Commit) == 64 {
		version, extensions = "1", "[extensions]\n\tobjectformat = sha256\n"
	}
	return "[core]\n\trepositoryformatversion = " + version +
		"\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = false\n" +
		extensions + "[remote \"origin\"]\n\turl = " + target.Repository.URL + ".git\n"
}

func (git *sourceGit) checkout(ctx context.Context, target Target) error {
	tree, err := git.run(ctx, 128, "rev-parse", "--verify", target.Commit+"^{tree}")
	if err != nil {
		return err
	}
	if string(tree) != target.Tree+"\n" {
		return errors.New("fetched source commit/tree identity mismatch")
	}
	listing, err := git.run(ctx, maxTreeListingBytes, "ls-tree", "-r", "-t", "-l", "-z", "--full-tree", target.Tree)
	if err != nil {
		return err
	}
	if err := validateCheckout(listing, len(target.Tree)); err != nil {
		return err
	}
	if _, err := git.run(ctx, 4096, "checkout", "--quiet", "--detach", "--no-recurse-submodules", target.Commit, "--"); err != nil {
		return err
	}
	identities, err := git.run(ctx, 256, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return err
	}
	if string(identities) != target.Commit+"\n" {
		return errors.New("materialized source HEAD is not the selected commit")
	}
	tree, err = git.run(ctx, 128, "rev-parse", "--verify", "HEAD^{tree}")
	if err != nil {
		return err
	}
	if string(tree) != target.Tree+"\n" {
		return errors.New("materialized source HEAD tree is not the selected tree")
	}
	head, err := os.ReadFile(filepath.Join(git.root, ".git", "HEAD"))
	if err != nil {
		return fmt.Errorf("verify detached source HEAD: %w", err)
	}
	if string(head) != target.Commit+"\n" {
		return errors.New("materialized source HEAD is not detached")
	}
	return checkDisk(ctx, git.root)
}

func validateCheckout(listing []byte, identityLength int) error {
	totalBytes, count := int64(0), 0
	seen := make(map[string]bool)
	for len(listing) != 0 {
		end := bytes.IndexByte(listing, 0)
		if end < 0 {
			return errors.New("malformed fetched source tree listing")
		}
		header, name, found := strings.Cut(string(listing[:end]), "\t")
		listing = listing[end+1:]
		fields := strings.Fields(header)
		if !found || len(fields) != 4 || !validSourcePath(name) || seen[name] ||
			!validObjectID(fields[2]) || len(fields[2]) != identityLength {
			return errors.New("fetched source contains an unsafe or ambiguous path")
		}
		count++
		if count > maxTreeEntries {
			return errSourceLimit
		}
		seen[name] = true
		if fields[0] == "040000" && fields[1] == "tree" && fields[3] == "-" {
			continue
		}
		if (fields[0] != "100644" && fields[0] != "100755") || fields[1] != "blob" {
			return errors.New("source symlinks, submodules, and special files are not supported")
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > maxCheckoutBytes-totalBytes {
			return errSourceLimit
		}
		totalBytes += size
	}
	return nil
}

func validSourcePath(name string) bool {
	if name == "" || len(name) > maxPathBytes || !utf8.ValidString(name) ||
		strings.ContainsAny(name, `\:`) || strings.ContainsFunc(name, unicode.IsControl) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxPathDepth {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 ||
			strings.EqualFold(strings.TrimRight(part, ". "), ".git") {
			return false
		}
	}
	return true
}

func (git *sourceGit) run(ctx context.Context, outputLimit int, arguments ...string) ([]byte, error) {
	operation, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	command, err := git.command(operation, arguments)
	if err != nil {
		return nil, err
	}
	output := &limitedOutput{limit: outputLimit, cancel: cancel}
	command.Stdout, command.Stderr = output, io.Discard
	err = git.runCommand(command)
	if output.overflow {
		return nil, errSourceLimit
	}
	if operation.Err() != nil {
		return nil, context.Cause(operation)
	}
	if err != nil {
		// Git can print remote-controlled content. Return the operation, never
		// stderr, credential prompts, response bodies, or arbitrary source text.
		return nil, fmt.Errorf("anonymous source Git %s failed: %w", arguments[0], err)
	}
	return output.buffer.Bytes(), nil
}

type limitedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (output *limitedOutput) Write(content []byte) (int, error) {
	if len(content) > output.limit-output.buffer.Len() {
		output.overflow = true
		output.cancel()
		return 0, errSourceLimit
	}
	return output.buffer.Write(content)
}

func checkDisk(ctx context.Context, root string) error {
	total, count := int64(0), 0
	return filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && name != root {
				return nil
			}
			return fmt.Errorf("inspect private source disk usage: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > 4*maxTreeEntries {
			return errSourceLimit
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected symlink in source staging directory")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect source staging file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxDiskBytes-total {
			return errSourceLimit
		}
		total += info.Size()
		return nil
	})
}

func guardDisk(parent context.Context, root string) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	stopped, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(diskCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := checkDisk(ctx, root); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	return ctx, func() {
		close(stopped)
		<-finished
		cancel(nil)
	}
}
