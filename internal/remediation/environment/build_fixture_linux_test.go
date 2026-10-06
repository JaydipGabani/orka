//go:build linux

package environment

import "strings"

func validBuildFixtureOptions(options map[string]string) bool {
	return strings.Contains(options["source"], "@sha256:") &&
		strings.Contains(options["build-arg:FIXTURE_WORKER_IMAGE"], "@sha256:") &&
		options["target"] == "linux/container" && options["platform"] == "linux/amd64" &&
		strings.Contains(options["output"], "push=true")
}
