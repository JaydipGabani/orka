package buildjob

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
)

const (
	registryConfigDirectory   = "/home/worker/.docker"
	registryConfigFile        = "config.json"
	registryUIDAnnotation     = "remediation.orka.ai/build-registry-uid"
	registryVersionAnnotation = "remediation.orka.ai/build-registry-resource-version"
	maxRegistryConfigBytes    = 64 << 10
)

func (b *Backend) readRegistrySecret(ctx context.Context) (SecretIdentity, error) {
	if b.config.RegistrySecretName == "" {
		return SecretIdentity{}, nil
	}
	return b.readImmutableSecret(ctx, b.config.RegistrySecretName, corev1.SecretTypeDockerConfigJson,
		[]string{corev1.DockerConfigJsonKey})
}

func (b *Backend) validRegistryBinding(binding SecretIdentity) bool {
	if b.config.RegistrySecretName == "" {
		return binding == (SecretIdentity{})
	}
	return binding.Name == b.config.RegistrySecretName && binding.UID != "" && binding.ResourceVersion != ""
}

type registryAuthDocument struct {
	Auths map[string]registryBasicAuth `json:"auths"`
}

type registryBasicAuth struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email,omitempty"`
}

func validateRegistryConfig(directory, repository string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return failure(ErrInvalid, "registry-auth-projection-unavailable")
	}
	defer func() { _ = root.Close() }()
	// Secret projections use symlinks. os.Root confines their resolution to the
	// read-only projection; credentials never enter the staged local context.
	file, err := root.Open(registryConfigFile)
	if err != nil {
		return failure(ErrInvalid, "registry-auth-file-unavailable")
	}
	info, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, maxRegistryConfigBytes+1))
	closeErr := file.Close()
	if statErr != nil || !info.Mode().IsRegular() || readErr != nil || closeErr != nil ||
		len(body) > maxRegistryConfigBytes {
		return failure(ErrInvalid, "registry-auth-file-invalid")
	}
	return validateRegistryAuth(body, repository)
}

func validateRegistryAuth(body []byte, repository string) error {
	parsed, err := reference.ParseNormalizedNamed(repository)
	if err != nil || !outputRepository(repository) || len(body) > maxRegistryConfigBytes || !utf8.Valid(body) {
		return failure(ErrInvalid, "registry-auth-config-invalid")
	}
	var config registryAuthDocument
	// DisallowUnknownFields rejects credsStore, credHelpers, auth-provider
	// commands, custom headers, and every other non-basic-auth extension.
	if decodeStrict(body, &config) != nil || len(config.Auths) != 1 {
		return failure(ErrInvalid, "registry-auth-single-host-basic-config-required")
	}
	auth, found := config.Auths[reference.Domain(parsed)]
	if !found || !validRegistryBasicAuth(auth) {
		return failure(ErrInvalid, "registry-auth-output-host-or-basic-credentials-invalid")
	}
	return nil
}

func validRegistryBasicAuth(auth registryBasicAuth) bool {
	username, password := auth.Username, auth.Password
	if auth.Auth != "" {
		if len(auth.Auth) > 8192 {
			return false
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(auth.Auth)
		if err != nil || !utf8.Valid(decoded) {
			return false
		}
		user, pass, found := strings.Cut(string(decoded), ":")
		if !found || (username != "" && username != user) || (password != "" && password != pass) {
			return false
		}
		username, password = user, pass
	}
	if username == "" || len(username) > 256 || password == "" || len(password) > 4096 ||
		len(auth.Email) > 256 || strings.Contains(username, ":") {
		return false
	}
	for _, field := range []string{username, password, auth.Email} {
		for _, character := range field {
			if character < 0x20 || character == 0x7f {
				return false
			}
		}
	}
	return true
}
