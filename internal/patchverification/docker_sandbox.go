package patchverification

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

const dockerOwnerLabel = "ai.orka.patchverification.owner"
const dockerPrivateNamespace = "private"
const dockerNetworkNone = "none"
const dockerLogDriverNone = "none"
const dockerSeccompAllow = "SCMP_ACT_ALLOW"
const dockerSeccompEqual = "SCMP_CMP_EQ"
const dockerSeccompMaskedEqual = "SCMP_CMP_MASKED_EQ"

type dockerContainerSpec struct {
	name         string
	owner        string
	environment  Environment
	seccompPath  string
	network      string
	sourceDir    string
	checksDir    string
	launcherPath string
	command      []string
	clearEnv     []string
}

func dockerCreateArguments(spec dockerContainerSpec) []string {
	arguments := []string{
		"create", "--name", spec.name, "--label", dockerOwnerLabel + "=" + spec.owner,
		"--pull", "never", "--platform", spec.environment.Platform,
		"--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true", "--security-opt", "seccomp=" + spec.seccompPath,
		"--memory", "512m", "--memory-swap", "512m", "--cpus", "1", "--pids-limit", "128",
		"--ulimit", "nofile=256:256", "--ulimit", "fsize=268435456:268435456",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=268435456,mode=1777",
		"--shm-size", "8m", "--ipc", dockerPrivateNamespace, "--cgroupns", dockerPrivateNamespace,
		"--network", spec.network, "--init", "--no-healthcheck", "--restart", "no",
		"--stop-signal", "SIGTERM", "--stop-timeout", "2", "--log-driver", dockerLogDriverNone,
		"--attach", "stdout", "--attach", "stderr", "--interactive",
		"--env", "LD_PRELOAD=", "--env", "LD_LIBRARY_PATH=",
		"--entrypoint", "/usr/bin/env",
	}
	for _, name := range spec.clearEnv {
		arguments = append(arguments, "--env", name+"=")
	}
	if spec.network == dockerNetworkNone {
		arguments = append(arguments, "--dns", "127.0.0.1", "--dns-search", ".")
	}
	if spec.sourceDir != "" {
		arguments = append(arguments, "--mount", "type=bind,src="+spec.sourceDir+",dst=/src,readonly,bind-recursive=disabled", "--workdir", "/src")
	} else {
		arguments = append(arguments, "--workdir", "/tmp")
	}
	if spec.checksDir != "" {
		arguments = append(arguments, "--mount", "type=bind,src="+spec.checksDir+",dst=/checks,readonly,bind-recursive=disabled")
	}
	if spec.launcherPath != "" {
		arguments = append(arguments, "--mount", "type=bind,src="+spec.launcherPath+",dst="+dockerLauncherMount+",readonly,bind-recursive=disabled")
	}
	arguments = append(arguments, spec.environment.Image, "-i",
		"PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp",
		"LANG=C", "LC_ALL=C", "GOCACHE=/tmp/go-build", "GOMODCACHE=/tmp/go-mod",
		"GOPATH=/tmp/go", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off",
		"PYTHONDONTWRITEBYTECODE=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	keys := make([]string, 0, len(spec.environment.Variables))
	for key := range spec.environment.Variables {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		arguments = append(arguments, key+"="+spec.environment.Variables[key])
	}
	return append(arguments, spec.command...)
}

func dockerValidateInputs(manifest Manifest, sourceDir, checksDir string) error {
	if len(manifest.Environment.Services) > 8 {
		return errors.New("too many local fixtures")
	}
	for key, value := range manifest.Environment.Variables {
		switch key {
		case "CGO_ENABLED", "GOEXPERIMENT", "GOMAXPROCS", "TZ", "LANG", "LC_ALL":
		default:
			return errors.New("unsupported environment variable")
		}
		if len(value) > 1024 || strings.ContainsRune(value, 0) {
			return errors.New("invalid environment variable value")
		}
	}
	for _, directory := range []string{sourceDir, checksDir} {
		if err := dockerValidateDirectory(directory); err != nil {
			return err
		}
	}
	if sourceDir == checksDir || strings.HasPrefix(sourceDir, checksDir+"/") || strings.HasPrefix(checksDir, sourceDir+"/") {
		return errors.New("source and checks must be separate staged directories")
	}
	files, err := dockerValidateCheckFiles(manifest.Files, checksDir)
	if err != nil {
		return err
	}
	return dockerValidateCommands(manifest, files, checksDir)
}

func dockerValidateCheckFiles(frozenFiles []FrozenFile, checksDir string) (map[string]FrozenFile, error) {
	files := make(map[string]FrozenFile)
	directories := map[string]bool{".": true}
	for _, file := range frozenFiles {
		_, duplicate := files[file.Path]
		if file.Path == "" || file.Path == "." || path.Clean(file.Path) != file.Path || strings.HasPrefix(file.Path, "../") || path.IsAbs(file.Path) || strings.ContainsRune(file.Path, '\\') || duplicate || file.Digest != Digest(file.Content) {
			return nil, errors.New("invalid frozen check file path")
		}
		files[file.Path] = file
		for directory := path.Dir(file.Path); directory != "."; directory = path.Dir(directory) {
			directories[directory] = true
		}
	}
	seen := 0
	if err := filepath.WalkDir(checksDir, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("frozen check files are unavailable")
		}
		relative, err := filepath.Rel(checksDir, filename)
		if err != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("frozen check files cannot be symlinked")
		}
		if entry.IsDir() && directories[relative] {
			return nil
		}
		frozen, declared := files[relative]
		info, err := entry.Info()
		if err != nil || !declared || !info.Mode().IsRegular() || info.Size() != int64(len(frozen.Content)) || (info.Mode().Perm()&0111 != 0) != frozen.Executable {
			return errors.New("staged checks differ from the frozen file inventory")
		}
		opened, err := os.Open(filename)
		if err != nil {
			return errors.New("frozen check file could not be opened")
		}
		content, readErr := io.ReadAll(io.LimitReader(opened, int64(len(frozen.Content))+1))
		closeErr := opened.Close()
		if readErr != nil || closeErr != nil || len(content) != len(frozen.Content) || Digest(content) != frozen.Digest {
			return errors.New("staged check content does not match its frozen digest")
		}
		seen++
		return nil
	}); err != nil {
		return nil, err
	}
	if seen != len(files) {
		return nil, errors.New("a frozen check file is missing")
	}
	return files, nil
}

func dockerValidateCommands(manifest Manifest, files map[string]FrozenFile, checksDir string) error {
	commands := make([][]string, 0, len(manifest.Checks)+len(manifest.Environment.Services))
	for _, check := range manifest.Checks {
		if len(check.Stdin) > dockerDefaultOutputBytes {
			return errors.New("check input exceeds the local runner limit")
		}
		commands = append(commands, check.Command)
	}
	for _, service := range manifest.Environment.Services {
		commands = append(commands, service.Command)
	}
	for _, command := range commands {
		if len(command) == 0 {
			return errors.New("commands must execute declared frozen files under /checks")
		}
		_, declared := files[strings.TrimPrefix(command[0], "/checks/")]
		if !strings.HasPrefix(command[0], "/checks/") || !declared {
			return errors.New("commands must execute declared frozen files under /checks")
		}
		for _, argument := range command {
			if len(argument) > 8192 || strings.ContainsRune(argument, 0) {
				return errors.New("invalid frozen command argument")
			}
		}
		filename := filepath.Join(checksDir, strings.TrimPrefix(command[0], "/checks/"))
		resolved, err := filepath.EvalSymlinks(filename)
		if err != nil || resolved != filename {
			return errors.New("frozen executable is unavailable or symlinked")
		}
		info, err := os.Stat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return errors.New("frozen check file is not executable")
		}
	}
	return nil
}

func dockerValidateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" || strings.ContainsAny(directory, ",\r\n\x00") {
		return errors.New("an absolute staged directory is required")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("staged directory is unavailable or symlinked")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return errors.New("staged input is not a directory")
	}
	for ancestor := directory; ; ancestor = filepath.Dir(ancestor) {
		if _, err := os.Lstat(filepath.Join(ancestor, ".git")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("staged inputs must be outside Git worktrees")
		}
		if ancestor == "/" {
			break
		}
	}
	err = filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Name() == ".git" || (!entry.IsDir() && !entry.Type().IsRegular() && entry.Type() != os.ModeSymlink) {
			return errors.New("staged inputs cannot contain Git metadata or special files")
		}
		return nil
	})
	if err != nil {
		return errors.New("staged inputs could not be validated")
	}
	return nil
}

type dockerSeccompArgument struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

type dockerSeccompRule struct {
	Names    []string                `json:"names"`
	Action   string                  `json:"action"`
	ErrnoRet uint                    `json:"errnoRet,omitempty"`
	Args     []dockerSeccompArgument `json:"args,omitempty"`
}

type dockerSeccompProfile struct {
	DefaultAction   string              `json:"defaultAction"`
	DefaultErrnoRet uint                `json:"defaultErrnoRet"`
	Architectures   []string            `json:"architectures"`
	Syscalls        []dockerSeccompRule `json:"syscalls"`
}

func dockerSeccomp(platform, profile string) ([]byte, error) {
	architecture := map[string]string{dockerPlatformAMD64: "SCMP_ARCH_X86_64", dockerPlatformARM64: "SCMP_ARCH_AARCH64"}[platform]
	if architecture == "" || (profile != Offline && profile != LocalServices) {
		return nil, errors.New("unsupported seccomp platform or network profile")
	}
	allowed := strings.Fields(`
		accept accept4 access alarm arch_prctl bind brk capget chdir chmod chown chown32
		clock_getres clock_gettime clock_nanosleep close close_range connect copy_file_range
		creat dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_pwait epoll_pwait2 epoll_wait
		eventfd eventfd2 execve execveat exit exit_group faccessat faccessat2 fadvise64 fallocate
		fchdir fchmod fchmodat fchmodat2 fchown fchown32 fchownat fcntl fcntl64 fdatasync
		flock fork fstat fstat64 fstatat64 fstatfs fstatfs64 fsync ftruncate ftruncate64
		futex futex_time64 getcpu getcwd getdents getdents64 getegid getegid32 geteuid geteuid32
		getgid getgid32 getgroups getgroups32 getitimer getpeername getpgid getpgrp getpid
		getppid getpriority getrandom getresgid getresgid32 getresuid getresuid32 getrlimit
		get_robust_list getrusage getsid getsockname getsockopt gettid gettimeofday getuid getuid32
		getxattr inotify_add_watch inotify_init inotify_init1 inotify_rm_watch ioctl kill
		lchown lchown32 lgetxattr link linkat listen listxattr llistxattr llseek lseek lstat lstat64
		madvise membarrier mincore mkdir mkdirat mlock mlock2 mlockall mmap mmap2 mprotect
		mremap msync munlock munlockall munmap nanosleep newfstatat open openat pause
		pipe pipe2 poll ppoll prctl pread64 preadv preadv2 prlimit64 pselect6 pwrite64 pwritev
		pwritev2 read readahead readlink readlinkat readv recvfrom recvmmsg recvmsg rename
		renameat renameat2 restart_syscall rmdir rseq rt_sigaction rt_sigpending rt_sigprocmask
		rt_sigqueueinfo rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_tgsigqueueinfo
		sched_getaffinity sched_getattr sched_getparam sched_get_priority_max sched_get_priority_min
		sched_getscheduler sched_rr_get_interval sched_setaffinity sched_yield select sendfile
		sendfile64 sendmmsg sendmsg sendto setfsgid setfsgid32 setfsuid setfsuid32 setgid setgid32
		setgroups setgroups32 setitimer setpgid setpriority setregid setregid32 setresgid
		setresgid32 setresuid setresuid32 setreuid setreuid32 setrlimit setsid setsockopt
		set_tid_address setuid setuid32 set_robust_list shutdown sigaltstack signalfd signalfd4
		splice stat stat64 statfs statfs64 statx symlink symlinkat sync sync_file_range syncfs
		tee tgkill time timer_create timer_delete timer_getoverrun timer_gettime timer_settime
		timerfd_create timerfd_gettime timerfd_settime times tkill truncate truncate64 umask
		uname unlink unlinkat utime utimensat utimes vfork wait4 waitid waitpid write writev`)
	socketpairArguments := []dockerSeccompArgument{{Index: 0, Value: 1, Op: dockerSeccompEqual}}
	if profile == LocalServices {
		allowed = slices.DeleteFunc(allowed, func(name string) bool {
			return name == "sendto" || name == "sendmsg" || name == "sendmmsg"
		})
		socketpairArguments = append(socketpairArguments, dockerSeccompArgument{Index: 1, Value: ^uint64(0x80000 | 0x800), ValueTwo: 1, Op: dockerSeccompMaskedEqual})
	}
	rules := []dockerSeccompRule{
		{Names: allowed, Action: dockerSeccompAllow},
		{Names: []string{"clone"}, Action: dockerSeccompAllow, Args: []dockerSeccompArgument{{Index: 0, Value: 0x7e020000, Op: dockerSeccompMaskedEqual}}},
		{Names: []string{"clone3", "openat2"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: 38},
		{Names: []string{"socketpair"}, Action: dockerSeccompAllow, Args: socketpairArguments},
	}
	if profile == Offline {
		rules = append(rules, dockerSeccompRule{Names: []string{"socket"}, Action: dockerSeccompAllow, Args: []dockerSeccompArgument{{Index: 0, Value: 1, Op: dockerSeccompEqual}}})
	} else {
		rules = append(rules, dockerSeccompRule{Names: []string{"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"}, Action: dockerSeccompAllow})
		for _, send := range []struct {
			name  string
			index uint
		}{{"sendto", 3}, {"sendmsg", 2}, {"sendmmsg", 3}} {
			rules = append(rules, dockerSeccompRule{Names: []string{send.name}, Action: dockerSeccompAllow, Args: []dockerSeccompArgument{{Index: send.index, Value: 0x20000000, Op: dockerSeccompMaskedEqual}}})
		}
		for _, family := range []uint64{2, 10} {
			for _, protocol := range []uint64{0, 6} {
				rules = append(rules, dockerSeccompRule{Names: []string{"socket"}, Action: dockerSeccompAllow, Args: []dockerSeccompArgument{
					{Index: 0, Value: family, Op: dockerSeccompEqual},
					{Index: 1, Value: 15, ValueTwo: 1, Op: dockerSeccompMaskedEqual},
					{Index: 2, Value: protocol, Op: dockerSeccompEqual},
				}})
			}
		}
	}
	return json.Marshal(dockerSeccompProfile{DefaultAction: "SCMP_ACT_ERRNO", DefaultErrnoRet: 1, Architectures: []string{architecture}, Syscalls: rules})
}

func dockerSecurityOptionsMatch(options []string, profile []byte) bool {
	if len(options) != 2 || !slices.Contains(options, "no-new-privileges=true") {
		return false
	}
	var expected any
	if json.Unmarshal(profile, &expected) != nil {
		return false
	}
	for _, option := range options {
		if policy, found := strings.CutPrefix(option, "seccomp="); found {
			var actual any
			return json.Unmarshal([]byte(policy), &actual) == nil && reflect.DeepEqual(actual, expected)
		}
	}
	return false
}
