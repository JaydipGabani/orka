//go:build linux

package buildjob

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestWorkerLimitsDoNotCountOtherPodsSharingUID(t *testing.T) {
	const child = "ORKA_TEST_WORKER_LIMITS_CHILD"
	if os.Getenv(child) != "1" {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestWorkerLimitsDoNotCountOtherPodsSharingUID$")
		command.Env = append(os.Environ(), child+"=1")
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	var before, after, files unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NPROC, &before))
	require.NoError(t, LimitWorkerProcess())
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NPROC, &after))
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &files))
	require.Equal(t, before, after, "per-UID limits cannot enforce a per-Pod process budget")
	require.LessOrEqual(t, files.Cur, uint64(1024))
	require.LessOrEqual(t, files.Max, uint64(1024))
}
