package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/orka-agents/orka/internal/controller"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (c CopilotConfig) Validate(namespace string) error {
	if len(validation.IsDNS1123Label(namespace)) != 0 ||
		len(validation.IsDNS1123Label(c.RuntimeNamespace)) != 0 ||
		len(validation.IsDNS1123Label(c.ProxyNamespace)) != 0 ||
		c.RuntimeNamespace == namespace || c.RuntimeNamespace == c.ProxyNamespace ||
		!controller.ACPRuntimeImageAvailable(c.Image) || !remediationpolicy.ValidCopilotProxyEndpoint(c.ProxyEndpoint) ||
		len(c.IdentityReferences) < 2 || len(c.IdentityReferences) > 8 {
		return errors.New("governed Copilot remediation configuration is incomplete")
	}
	hasRoute, hasCredential := false, false
	seen := make(map[CopilotIdentityReference]bool)
	for _, ref := range c.IdentityReferences {
		if (ref.Kind != "ConfigMap" && ref.Kind != "Secret") ||
			ref.Namespace != c.ProxyNamespace || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || seen[ref] {
			return errors.New("copilot model route identity reference is invalid")
		}
		seen[ref] = true
		hasRoute = hasRoute || ref.Kind == "ConfigMap"
		hasCredential = hasCredential || ref.Kind == "Secret"
	}
	if !hasRoute || !hasCredential {
		return errors.New("copilot route and credential identities must both be frozen")
	}
	return nil
}

func (c CopilotConfig) Digest() (string, error) {
	raw, err := json.Marshal(struct {
		Version string        `json:"version"`
		Config  CopilotConfig `json:"config"`
	}{"orka.remediation.copilot-config/v1", c})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
