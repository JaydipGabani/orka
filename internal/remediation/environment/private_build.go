package environment

// HasPrivateBuildBoundary is only configuration eligibility. Execution still
// requires the pinned trusted worker, mTLS/registry identity checks and Dalec's
// network-isolated build phase. It is not remote attestation or disclosure approval.
func (a *Adapter) HasPrivateBuildBoundary() bool {
	if !a.HasBuildRegistrySecret() || a.config.BuildJobs.TLS == nil {
		return false
	}
	tls := a.config.BuildJobs.TLS
	return tls.CASecretName != "" && tls.ServerName != "" && tls.ClientSecretName != ""
}
