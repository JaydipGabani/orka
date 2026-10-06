package controllerlab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func freshValue() ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, failure(Infrastructure, "entropy-unavailable")
	}
	defer clear(random)
	result := make([]byte, hex.EncodedLen(len(random)))
	hex.Encode(result, random)
	return result, nil
}

func (a *Adapter) secret(s State, m metav1.ObjectMeta, existing runtime.Object) (runtime.Object, error) {
	// Recovery can adopt only immutable, well-formed material carrying the
	// persisted random intent and namespace owner. No key bytes enter State.
	if existing != nil {
		secret, ok := existing.(*corev1.Secret)
		if !ok || !validSecret(secret, s, a.now()) {
			return nil, failure(OwnershipLost, "invalid-immutable-lab-secret")
		}
		return &corev1.Secret{ObjectMeta: m, Immutable: new(true), Type: corev1.SecretTypeOpaque, Data: secret.DeepCopy().Data}, nil
	}
	data := map[string][]byte{}
	if m.Name == canaryName {
		value, err := freshValue()
		if err != nil {
			return nil, err
		}
		data["key"] = value
	} else {
		dns := observerDNS(s)
		if m.Name == controllerTLSName {
			dns = controllerName + "." + s.Namespaces[0] + ".svc"
		}
		cert, key, err := newCertificate(dns, a.now(), s.Deadline.Add(15*time.Minute))
		if err != nil {
			return nil, err
		}
		data["tls.crt"], data["tls.key"], data["ca.crt"] = cert, key, bytes.Clone(cert)
		if m.Name == adminSecretName {
			token, err := freshValue()
			if err != nil {
				return nil, err
			}
			data["admin-token"] = token
		}
	}
	return &corev1.Secret{ObjectMeta: m, Immutable: new(true), Type: corev1.SecretTypeOpaque, Data: data}, nil
}

func newCertificate(dns string, now, expiry time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, failure(Infrastructure, "tls-generation-failed")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, failure(Infrastructure, "tls-generation-failed")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic-controllerlab"},
		NotBefore: now.Add(-time.Minute), NotAfter: expiry, DNSNames: []string{dns},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, failure(Infrastructure, "tls-generation-failed")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, failure(Infrastructure, "tls-generation-failed")
	}
	defer clear(keyDER)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func validSecret(secret *corev1.Secret, s State, now time.Time) bool {
	if secret.Immutable == nil || !*secret.Immutable || secret.Type != corev1.SecretTypeOpaque {
		return false
	}
	if secret.Name == canaryName {
		return len(secret.Data) == 1 && digestPattern.Match(secret.Data["key"])
	}
	dns, count := observerDNS(s), 4
	if secret.Name == controllerTLSName {
		dns, count = controllerName+"."+s.Namespaces[0]+".svc", 3
	}
	if len(secret.Data) != count || len(secret.Data["tls.key"]) > 8192 || len(secret.Data["tls.crt"]) > 8192 ||
		!bytes.Equal(secret.Data["ca.crt"], secret.Data["tls.crt"]) {
		return false
	}
	pair, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil || len(pair.Certificate) != 1 {
		return false
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !cert.IsCA || cert.VerifyHostname(dns) != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	return count == 3 || digestPattern.Match(secret.Data["admin-token"])
}

func (a *Adapter) ownedSecret(ctx context.Context, s State, object ObjectRef) (*corev1.Secret, error) {
	receipt := receiptFor(s, object)
	if receipt == nil || receipt.Deleted {
		return nil, failure(OwnershipLost, "secret-receipt-required")
	}
	value, err := a.kube.CoreV1().Secrets(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
	if err != nil {
		return nil, failure(Infrastructure, "lab-secret-unavailable")
	}
	if value.UID != receipt.Object.UID || !owns(s, object, receipt.IntentDigest, value) || !validSecret(value, s, a.now()) {
		return nil, failure(OwnershipLost, "lab-secret-identity-changed")
	}
	return value, nil
}
