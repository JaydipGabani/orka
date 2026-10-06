//go:build linux

package source

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const gitPrlimit = "/usr/bin/prlimit"

func trustedGit() (string, error) {
	if !executableFile(gitPrlimit) {
		return "", errors.New("public source materialization requires executable util-linux /usr/bin/prlimit")
	}
	for _, binary := range []string{"/usr/bin/git", "/bin/git"} {
		if executableFile(binary) {
			return binary, nil
		}
	}
	return "", errors.New("public source materialization requires trusted system Git")
}

func executableFile(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

func (git *sourceGit) command(ctx context.Context, arguments []string) (*exec.Cmd, error) {
	fileLimit := strconv.Itoa(gitMaxFileBytes)
	options := make([]string, 0, 96+len(arguments))
	options = append(options,
		"--as=536870912:536870912", "--cpu=30:30", "--fsize="+fileLimit+":"+fileLimit,
		"--core=0:0", "--nofile=256:256", "--", git.binary,
	)
	for _, setting := range []string{
		"core.hooksPath=/dev/null", "core.attributesFile=/dev/null", "core.excludesFile=/dev/null",
		"core.fsmonitor=false", "core.untrackedCache=false", "core.protectHFS=true", "core.protectNTFS=true",
		"credential.helper=", "credential.interactive=never", "core.askPass=",
		"protocol.allow=never", "protocol.https.allow=always", "protocol.version=2",
		"http.followRedirects=false", "http.proxy=", "http.extraHeader=", "http.cookieFile=",
		"http.saveCookies=false", "http.sslVerify=true", "http.lowSpeedLimit=1024", "http.lowSpeedTime=15",
		"submodule.recurse=false", "fetch.recurseSubmodules=false",
		"filter.lfs.required=false", "filter.lfs.clean=", "filter.lfs.smudge=", "filter.lfs.process=",
		"fetch.fsckObjects=true", "transfer.fsckObjects=true", "fetch.unpackLimit=0", "transfer.unpackLimit=0",
		"fetch.writeCommitGraph=false", "gc.auto=0", "maintenance.auto=false", "pack.threads=1",
		"core.autocrlf=false", "core.safecrlf=false", "core.logAllRefUpdates=false",
	} {
		options = append(options, "-c", setting)
	}
	options = append(options, "--git-dir="+filepath.Join(git.root, ".git"), "--work-tree="+git.root)
	command := exec.CommandContext(ctx, gitPrlimit, append(options, arguments...)...)
	command.Dir = git.root
	command.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=/dev/null", "XDG_CONFIG_HOME=/dev/null", "LANG=C", "LC_ALL=C", "TZ=UTC",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false", "GIT_OPTIONAL_LOCKS=0", "GIT_PROTOCOL_FROM_USER=0", "GIT_ALLOW_PROTOCOL=https",
		"GIT_LITERAL_PATHSPECS=1", "GIT_LFS_SKIP_SMUDGE=1", "TMPDIR=" + filepath.Join(git.root, ".git", "tmp"),
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	return command, nil
}

func publishNoReplace(staging, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}

func sourceFileIdentity(info os.FileInfo) (directoryIdentity, error) {
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || (!info.IsDir() && native.Nlink != 1) {
		return directoryIdentity{}, errors.New("managed source files must be singly linked and owned by the current user")
	}
	return directoryIdentity{Device: native.Dev, Inode: native.Ino}, nil
}

func openSourceFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}
