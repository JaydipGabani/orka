package buildjob

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	caCertificateKey        = "ca.crt"
	caUIDAnnotation         = "remediation.orka.ai/build-ca-uid"
	caVersionAnnotation     = "remediation.orka.ai/build-ca-resource-version"
	clientUIDAnnotation     = "remediation.orka.ai/build-client-uid"
	clientVersionAnnotation = "remediation.orka.ai/build-client-resource-version"
)

func (b *Backend) readTLSSecrets(ctx context.Context) (TLSSecrets, error) {
	ca, err := b.readImmutableSecret(ctx, b.config.TLS.CASecretName, corev1.SecretTypeOpaque, []string{caCertificateKey})
	if err != nil {
		return TLSSecrets{}, err
	}
	client, err := b.readImmutableSecret(ctx, b.config.TLS.ClientSecretName, corev1.SecretTypeTLS,
		[]string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey})
	if err != nil {
		return TLSSecrets{}, err
	}
	return TLSSecrets{CA: ca, Client: client}, nil
}

func (b *Backend) readImmutableSecret(ctx context.Context, name string, kind corev1.SecretType, keys []string) (SecretIdentity, error) {
	secret, err := b.config.APIReader.CoreV1().Secrets(b.config.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return SecretIdentity{}, apiFailure(ctx, err, "build-credential-secret-unavailable")
	}
	if secret.Name != name || secret.Namespace != b.config.Namespace || secret.UID == "" ||
		secret.ResourceVersion == "" || secret.DeletionTimestamp != nil || secret.Type != kind ||
		secret.Immutable == nil || !*secret.Immutable || len(secret.Data) != len(keys) || len(secret.StringData) != 0 {
		return SecretIdentity{}, failure(ErrIdentity, "build-credential-secret-metadata-or-shape-invalid")
	}
	for _, key := range keys {
		if len(secret.Data[key]) == 0 {
			return SecretIdentity{}, failure(ErrIdentity, "build-credential-secret-required-key-missing")
		}
	}
	return SecretIdentity{Name: name, UID: secret.UID, ResourceVersion: secret.ResourceVersion}, nil
}

func (b *Backend) verifyClientSecrets(ctx context.Context, r Receipt) error {
	actual, err := b.readTLSSecrets(ctx)
	if err != nil {
		return err
	}
	if actual != r.TLSSecrets {
		return failure(ErrIdentity, "build-tls-secret-identity-changed")
	}
	registry, err := b.readRegistrySecret(ctx)
	if err != nil {
		return err
	}
	if registry != r.RegistrySecret {
		return failure(ErrIdentity, "build-registry-secret-identity-changed")
	}
	return nil
}

func (b *Backend) validTLSBinding(binding TLSSecrets) bool {
	return binding.CA.Name == b.config.TLS.CASecretName && binding.Client.Name == b.config.TLS.ClientSecretName &&
		binding.CA.UID != "" && binding.CA.ResourceVersion != "" &&
		binding.Client.UID != "" && binding.Client.ResourceVersion != ""
}
