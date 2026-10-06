package provenance

import (
	"errors"
	"reflect"
	"slices"
)

const SchemaVersion = 1

type EvidenceStatus string

const (
	EvidencePartial  EvidenceStatus = "partial"
	EvidenceVerified EvidenceStatus = "verified"

	MissingRecipeCommit       = "recipe_commit"
	MissingUpstreamCommit     = "upstream_commit"
	MissingVersion            = "version"
	MissingRevision           = "revision"
	MissingTarget             = "selected_target"
	MissingPlatform           = "selected_platform"
	MissingFrontendDigest     = "frontend_image_digest"
	MissingOriginalDigest     = "observed_original_image_digest"
	MissingControlDigest      = "rebuilt_control_image_digest"
	MissingAcquisition        = "recipe_acquisition_attestation"
	MissingOriginalBinding    = "published_image_recipe_attestation"
	MissingControlBinding     = "rebuilt_control_recipe_attestation"
	MissingDependencyIdentity = "resolved_dependency_identities"
	MissingRecipeMapping      = "git_recipe_mapping_verification"
	MissingSourceAttestation  = "upstream_commit_attestation"
	MissingWorkerDigest       = "worker_image_digest"
)

// ImageIdentity never infers a digest from a tag. Reference retains the supplied
// identity; Digest requires an explicit sha256 reference or caller-verified
// attested inputs. Attested references are normalized to include the digest.
type ImageIdentity struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

type Patch struct {
	Path        string `json:"path"`
	Digest      string `json:"digest"`
	InputDigest string `json:"inputDigest"`
	Source      string `json:"source"`
	Strip       int    `json:"strip"`
}

type BuildTarget struct {
	Name      string   `json:"name"`
	Platforms []string `json:"platforms"`
}

type Recipe struct {
	SchemaVersion               int                  `json:"schemaVersion"`
	RecipeRepository            string               `json:"recipeRepository,omitempty"`
	RecipeCommit                string               `json:"recipeCommit"`
	Path                        string               `json:"path"`
	ContentDigest               string               `json:"contentDigest"`
	BaseInputsDigest            string               `json:"baseInputsDigest"`
	UpstreamSource              string               `json:"upstreamSource"`
	UpstreamRepoURL             string               `json:"upstreamRepoURL"`
	UpstreamCommit              string               `json:"upstreamCommit"`
	Version                     string               `json:"version"`
	Revision                    string               `json:"revision"`
	Target                      string               `json:"target"`
	Platform                    string               `json:"platform"`
	Frontend                    ImageIdentity        `json:"frontend"`
	FrontendSyntax              ImageIdentity        `json:"frontendSyntax"`
	Worker                      ImageIdentity        `json:"worker"`
	OrderedPatches              []Patch              `json:"orderedPatches"`
	ModuleReplacements          []string             `json:"moduleReplacements"`
	BuildEnvironment            map[string]string    `json:"buildEnvironment"`
	BuildNetworkMode            string               `json:"buildNetworkMode,omitempty"`
	Arguments                   map[string]string    `json:"arguments"`
	BuildTargets                []BuildTarget        `json:"buildTargets"`
	ObservedOriginalImage       ImageIdentity        `json:"observedOriginalImage"`
	RebuiltControlImage         ImageIdentity        `json:"rebuiltControlImage"`
	EvidenceStatus              EvidenceStatus       `json:"evidenceStatus"`
	Missing                     []string             `json:"missing"`
	RecipeMappingStatus         MappingStatus        `json:"recipeMappingStatus"`
	RecipeMappingEvidenceDigest string               `json:"recipeMappingEvidenceDigest,omitempty"`
	UpstreamCommitStatus        SourceCommitStatus   `json:"upstreamCommitStatus"`
	AttestedInputs              *AttestedBuildInputs `json:"attestedInputs,omitempty"`
}

// Metadata holds acquisition context and optional caller-verified attestation
// bindings. Path and files keys are repository-relative. ExpectedDigests checks supplied
// bytes against previously recorded sha256 digests; it does not establish origin.
// RecipeCommit identifies the base recipe checkout, including for a candidate
// with a local appended-patch overlay. ExpectedVersion and ExpectedRevision
// constrain actual spec values; they are never overrides or derived from a tag
// or commit message. AttestedInputs and verified mapping labels are trusted
// caller assertions, not raw unverified SLSA payloads.
type Metadata struct {
	RecipeRepository            string
	RecipeCommit                string
	Path                        string
	UpstreamSource              string
	Target                      string
	Platform                    string
	ObservedOriginalImage       string
	RebuiltControlImage         string
	ExpectedDigests             map[string]string
	ExpectedVersion             string
	ExpectedRevision            string
	RecipeMappingStatus         MappingStatus
	RecipeMappingEvidenceDigest string
	AttestedInputs              *AttestedBuildInputs
}

// Compare checks equality of recipe inputs, not image equivalence. It does not
// authorize any patch addition. Both records must have immutable base identities;
// acquisition, dependency resolution and image attestations remain external.
func Compare(baseline, candidate Recipe) error {
	return compare(baseline, candidate, "")
}

// CompareWithAdditionalPatch permits exactly one final patch, authorized by its
// sha256 digest by the caller, against the selected upstream source. In
// particular, a candidate's own claims do not authorize its patch delta.
func CompareWithAdditionalPatch(baseline, candidate Recipe, additionalPatchDigest string) error {
	digest, err := canonicalDigest(additionalPatchDigest)
	if err != nil {
		return errors.New("provenance comparison requires an explicit additional patch digest")
	}
	return compare(baseline, candidate, digest)
}

func compare(baseline, candidate Recipe, additionalDigest string) error {
	if err := comparableRecipe(baseline); err != nil {
		return err
	}
	if err := comparableRecipe(candidate); err != nil {
		return err
	}
	baseInputs, candidateInputs := baseline, candidate
	baseInputs.ContentDigest, candidateInputs.ContentDigest = "", ""
	baseInputs.OrderedPatches, candidateInputs.OrderedPatches = nil, nil
	baseInputs.EvidenceStatus, candidateInputs.EvidenceStatus = "", ""
	baseInputs.Missing, candidateInputs.Missing = nil, nil
	if !reflect.DeepEqual(baseInputs, candidateInputs) {
		return errors.New("provenance comparison changed base recipe inputs")
	}
	if additionalDigest == "" {
		if baseline.ContentDigest != candidate.ContentDigest ||
			!slices.Equal(baseline.OrderedPatches, candidate.OrderedPatches) {
			return errors.New("provenance comparison contains an unauthorized recipe or patch change")
		}
		return nil
	}
	existing := len(baseline.OrderedPatches)
	if len(candidate.OrderedPatches) != existing+1 ||
		!slices.Equal(baseline.OrderedPatches, candidate.OrderedPatches[:existing]) {
		return errors.New("provenance comparison must preserve the existing patch series and append exactly one patch")
	}
	added := candidate.OrderedPatches[existing]
	if added.Digest != additionalDigest || added.Source != baseline.UpstreamSource {
		return errors.New("provenance comparison appended an unauthorized patch")
	}
	if baseline.ContentDigest == candidate.ContentDigest {
		return errors.New("provenance comparison lacks a recipe declaring the appended patch")
	}
	return nil
}

func comparableRecipe(recipe Recipe) error {
	if recipe.SchemaVersion != SchemaVersion {
		return errors.New("provenance comparison uses an unsupported schema version")
	}
	if recipe.EvidenceStatus != EvidencePartial && recipe.EvidenceStatus != EvidenceVerified {
		return errors.New("provenance comparison has an invalid evidence status")
	}
	if recipe.EvidenceStatus == EvidenceVerified && len(recipe.Missing) != 0 {
		return errors.New("provenance comparison cannot treat incomplete evidence as verified")
	}
	for _, missing := range recipe.Missing {
		switch missing {
		case MissingRecipeCommit, MissingUpstreamCommit, MissingVersion, MissingRevision,
			MissingTarget, MissingPlatform, MissingFrontendDigest, MissingOriginalDigest:
			return errors.New("provenance comparison requires complete immutable recipe inputs")
		}
	}
	if !safePath(recipe.Path) || !safeName(recipe.UpstreamSource) ||
		!exactCommit(recipe.RecipeCommit) || !exactCommit(recipe.UpstreamCommit) ||
		!safeRepository(recipe.UpstreamRepoURL) || !safeIdentifier(recipe.RecipeRepository) ||
		!safeVersion(recipe.Version) || !validRevision(recipe.Revision) ||
		!safePath(recipe.Target) || !validPlatform(recipe.Platform) {
		return errors.New("provenance comparison requires complete immutable recipe inputs")
	}
	for _, digest := range []string{recipe.ContentDigest, recipe.BaseInputsDigest} {
		canonical, err := canonicalDigest(digest)
		if err != nil || canonical != digest {
			return errors.New("provenance comparison requires canonical input digests")
		}
	}
	if err := comparableImages(recipe); err != nil {
		return err
	}
	if err := comparableEvidence(recipe); err != nil {
		return err
	}
	return comparablePatches(recipe.OrderedPatches)
}

func comparablePatches(patches []Patch) error {
	seen := make(map[string]bool, len(patches))
	for _, patch := range patches {
		digest, err := canonicalDigest(patch.Digest)
		inputDigest, inputErr := canonicalDigest(patch.InputDigest)
		if err != nil || digest != patch.Digest || !safePath(patch.Path) ||
			inputErr != nil || inputDigest != patch.InputDigest || !safeName(patch.Source) ||
			patch.Strip < 0 || patch.Strip > maxPatchStrip || seen[patch.Path] {
			return errors.New("provenance comparison contains an invalid patch identity")
		}
		seen[patch.Path] = true
	}
	return nil
}

func comparableImages(recipe Recipe) error {
	for index, image := range []ImageIdentity{recipe.Frontend, recipe.ObservedOriginalImage, recipe.RebuiltControlImage} {
		parsed, err := parseImage(image.Reference, index == 0)
		if err != nil || parsed != image || (index < 2 && image.Digest == "") {
			return errors.New("provenance comparison requires explicit immutable image identities")
		}
	}
	return nil
}
