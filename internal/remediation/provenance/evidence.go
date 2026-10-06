package provenance

import (
	"errors"
	"strings"

	"github.com/distribution/reference"
)

type MappingStatus string

const (
	MappingUnknown  MappingStatus = "unknown"
	MappingInferred MappingStatus = "inferred"
	MappingVerified MappingStatus = "verified"
)

type SourceCommitStatus string

const (
	SourceUnverified SourceCommitStatus = "unverified"
	SourceAttested   SourceCommitStatus = "attested"
)

var (
	ErrVersionMismatch        = errors.New("provenance recipe version does not match the required version")
	ErrRevisionMismatch       = errors.New("provenance recipe revision does not match the required revision")
	ErrAttestedInputsMismatch = errors.New("provenance attested build inputs are incomplete or inconsistent")
)

// ConfigSource preserves a caller-verified build-context claim. In particular,
// URI "input:context" and a spec Path do not identify a Git recipe commit.
type ConfigSource struct {
	URI  string `json:"uri"`
	Path string `json:"path"`
}

// AttestedBuildInputs contains normalized SLSA claims only after the caller has
// verified the statement and its subject/policy. StatementDigest identifies that
// evidence; a digest alone does not authenticate a statement. ParseDalec checks
// these bindings but performs no signature verification or payload acquisition.
// Frontend and Worker accept a pinned OCI reference, or a named OCI reference
// with a separate explicit Digest. No tag is resolved by this package.
type AttestedBuildInputs struct {
	StatementDigest    string        `json:"statementDigest"`
	SubjectImageDigest string        `json:"subjectImageDigest"`
	UpstreamRepoURL    string        `json:"upstreamRepoURL"`
	UpstreamCommit     string        `json:"upstreamCommit"`
	Frontend           ImageIdentity `json:"frontend"`
	Worker             ImageIdentity `json:"worker"`
	ConfigSource       ConfigSource  `json:"configSource"`
}

func (recipe Recipe) matchExpectedIdentity(metadata Metadata) error {
	if (metadata.ExpectedVersion != "" && !safeVersion(metadata.ExpectedVersion)) ||
		(metadata.ExpectedRevision != "" && !validRevision(metadata.ExpectedRevision)) {
		return errors.New("provenance expected version or revision is invalid")
	}
	if metadata.ExpectedVersion != "" && recipe.Version != metadata.ExpectedVersion {
		return ErrVersionMismatch
	}
	if metadata.ExpectedRevision != "" && recipe.Revision != metadata.ExpectedRevision {
		return ErrRevisionMismatch
	}
	if (metadata.AttestedInputs != nil || metadata.RecipeMappingStatus == MappingVerified) &&
		(metadata.ExpectedVersion == "" || metadata.ExpectedRevision == "") {
		return errors.New("provenance verified evidence requires an explicit expected version and revision")
	}
	return nil
}

func (recipe *Recipe) readEvidence(metadata Metadata) error {
	recipe.RecipeMappingStatus = metadata.RecipeMappingStatus
	if recipe.RecipeMappingStatus == "" {
		recipe.RecipeMappingStatus = MappingUnknown
		if recipe.RecipeCommit != "" {
			recipe.RecipeMappingStatus = MappingInferred
		}
	}
	if metadata.RecipeMappingEvidenceDigest != "" {
		digest, err := canonicalDigest(metadata.RecipeMappingEvidenceDigest)
		if err != nil {
			return errors.New("provenance recipe mapping requires a canonical evidence digest")
		}
		recipe.RecipeMappingEvidenceDigest = digest
	}
	recipe.UpstreamCommitStatus = SourceUnverified
	if metadata.AttestedInputs == nil {
		recipe.Missing = append(recipe.Missing, MissingSourceAttestation, MissingWorkerDigest)
	} else {
		attested, err := bindAttestedInputs(*recipe, *metadata.AttestedInputs)
		if err != nil {
			return err
		}
		recipe.AttestedInputs = &attested
		recipe.UpstreamCommitStatus = SourceAttested
		recipe.Frontend, recipe.Worker = attested.Frontend, attested.Worker
	}
	if err := validRecipeMapping(*recipe); err != nil {
		return err
	}
	if recipe.RecipeMappingStatus != MappingVerified {
		recipe.Missing = append(recipe.Missing, MissingRecipeMapping)
	}
	if recipe.Frontend.Digest == "" {
		recipe.Missing = append(recipe.Missing, MissingFrontendDigest)
	}
	return nil
}

func validRecipeMapping(recipe Recipe) error {
	if recipe.RecipeMappingEvidenceDigest != "" {
		digest, err := canonicalDigest(recipe.RecipeMappingEvidenceDigest)
		if err != nil || digest != recipe.RecipeMappingEvidenceDigest {
			return errors.New("provenance recipe mapping has an invalid evidence digest")
		}
	}
	switch recipe.RecipeMappingStatus {
	case MappingUnknown:
	case MappingInferred:
		if !exactCommit(recipe.RecipeCommit) {
			return errors.New("provenance inferred recipe mapping requires an exact recipe commit")
		}
	case MappingVerified:
		if recipe.RecipeMappingEvidenceDigest == "" || recipe.RecipeRepository == "" ||
			!exactCommit(recipe.RecipeCommit) || recipe.ObservedOriginalImage.Digest == "" {
			return errors.New("provenance verified recipe mapping requires independent evidence and immutable identities")
		}
		if recipe.AttestedInputs != nil && recipe.RecipeMappingEvidenceDigest == recipe.AttestedInputs.StatementDigest {
			return errors.New("provenance source attestation is not independent Git recipe mapping evidence")
		}
	default:
		return errors.New("provenance recipe mapping has an unsupported status")
	}
	return nil
}

func bindAttestedInputs(recipe Recipe, input AttestedBuildInputs) (AttestedBuildInputs, error) {
	statement, statementErr := canonicalDigest(input.StatementDigest)
	subject, subjectErr := canonicalDigest(input.SubjectImageDigest)
	if statementErr != nil || subjectErr != nil || subject != recipe.ObservedOriginalImage.Digest ||
		!safeRepository(input.UpstreamRepoURL) || !exactCommit(input.UpstreamCommit) ||
		input.UpstreamRepoURL != recipe.UpstreamRepoURL ||
		strings.ToLower(input.UpstreamCommit) != recipe.UpstreamCommit {
		return AttestedBuildInputs{}, ErrAttestedInputsMismatch
	}
	if input.ConfigSource.URI == "" || !safeIdentifier(input.ConfigSource.URI) ||
		!safePath(input.ConfigSource.Path) || input.ConfigSource.Path != recipe.Path {
		return AttestedBuildInputs{}, ErrAttestedInputsMismatch
	}
	frontend, err := attestedImage(input.Frontend)
	if err != nil || !frontendMatchesSyntax(recipe.FrontendSyntax, frontend) {
		return AttestedBuildInputs{}, ErrAttestedInputsMismatch
	}
	worker, err := attestedImage(input.Worker)
	if err != nil {
		return AttestedBuildInputs{}, ErrAttestedInputsMismatch
	}
	input.StatementDigest, input.SubjectImageDigest = statement, subject
	input.UpstreamCommit = strings.ToLower(input.UpstreamCommit)
	input.Frontend, input.Worker = frontend, worker
	return input, nil
}

func attestedImage(input ImageIdentity) (ImageIdentity, error) {
	image, err := parseImage(input.Reference, true)
	if err != nil || image.Reference == "" {
		return ImageIdentity{}, ErrAttestedInputsMismatch
	}
	if input.Digest != "" {
		digest, err := canonicalDigest(input.Digest)
		if err != nil || (image.Digest != "" && image.Digest != digest) {
			return ImageIdentity{}, ErrAttestedInputsMismatch
		}
		if image.Digest == "" {
			image, err = parseImage(image.Reference+"@"+digest, true)
			if err != nil {
				return ImageIdentity{}, ErrAttestedInputsMismatch
			}
		}
	}
	if image.Digest == "" {
		return ImageIdentity{}, ErrAttestedInputsMismatch
	}
	return image, nil
}

func frontendMatchesSyntax(syntax, attested ImageIdentity) bool {
	parsed, err := parseImage(syntax.Reference, true)
	if err != nil || parsed != syntax {
		return false
	}
	if syntax.Reference == "" {
		return true
	}
	declared, err := reference.ParseNormalizedNamed(syntax.Reference)
	if err != nil {
		return false
	}
	resolved, err := reference.ParseNormalizedNamed(attested.Reference)
	if err != nil || declared.Name() != resolved.Name() ||
		(syntax.Digest != "" && syntax.Digest != attested.Digest) {
		return false
	}
	declaredTag, declaredTagged := declared.(reference.Tagged)
	resolvedTag, resolvedTagged := resolved.(reference.Tagged)
	return !declaredTagged || !resolvedTagged || declaredTag.Tag() == resolvedTag.Tag()
}

func comparableEvidence(recipe Recipe) error {
	if err := validRecipeMapping(recipe); err != nil {
		return err
	}
	switch recipe.UpstreamCommitStatus {
	case SourceUnverified:
		if recipe.AttestedInputs != nil || recipe.Worker != (ImageIdentity{}) || recipe.Frontend != recipe.FrontendSyntax {
			return ErrAttestedInputsMismatch
		}
	case SourceAttested:
		if recipe.AttestedInputs == nil {
			return ErrAttestedInputsMismatch
		}
		attested, err := bindAttestedInputs(recipe, *recipe.AttestedInputs)
		if err != nil || attested != *recipe.AttestedInputs ||
			recipe.Frontend != attested.Frontend || recipe.Worker != attested.Worker {
			return ErrAttestedInputsMismatch
		}
	default:
		return errors.New("provenance source commit has an unsupported evidence status")
	}
	return nil
}
