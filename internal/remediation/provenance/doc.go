// Package provenance records downstream build inputs for report-to-patch
// planning. It is an offline parser and input-delta guard, not a build executor,
// source acquisition client, image attestor, or image-equivalence decision.
//
// # Input contract
//
// ParseDalec consumes one UTF-8 YAML document and an in-memory, repository-relative
// files map containing the recipe at Metadata.Path and exactly its referenced
// patch files. The recipe bytes must match spec byte for byte. Context patch files
// are relative to the supplied build context root, not the recipe directory.
// Inline patch files must also be supplied under their source name and match the
// decoded literal contents byte for byte. No line-ending or whitespace repair is
// performed. ExpectedDigests, when supplied, verifies exact supplied file bytes.
// Acquisition must separately establish that these bytes came from RecipeCommit;
// the repository identifier can be private and is never fetched.
//
// ExpectedVersion and ExpectedRevision are optional exact constraints on values
// extracted from the actual spec/args. They never override those values.
// ErrVersionMismatch and ErrRevisionMismatch are safe sentinel errors for a
// mismatched recipe. Image tags and commit messages are not parsed for revision
// guesses: a "bump16" message cannot turn a spec at revision 17 or 21 into 16.
//
// Version 1 supports HTTPS Git sources with full 40- or 64-hex object IDs,
// args, version/revision, build env/steps, package dependencies, target overrides,
// and sources.<name>.generate[].gomod with paths and edits.replace. Replacement
// entries accept Dalec's old[@version] => new@version notation and the legacy
// old[@version]=new@version parser notation. Actual frontend compatibility is
// established by the pinned build, not parsing. Local module replacements
// and other generators are unsupported. Multiple Git sources require an explicit
// Metadata.UpstreamSource. One ordered patch series may target that source.
// Patches use source/path/strip, with an omitted strip meaning 1. Local sources
// are default-context files or inline.file.contents, never remote patch fetches.
// Other non-Git sources, unused local sources, aliases, merges, duplicate or
// case-colliding keys, extra documents and unknown typed fields fail closed.
// Local patch contexts may use unique literal relative include paths; glob
// filters and filtered Git/inline sources remain unsupported. The include
// paths must admit each referenced patch and enter its patch-input.v2 digest.
// Changelog entries and existing name/files-only image metadata tests are
// preserved in the base identity. Arbitrary test commands/mounts and content
// assertions remain outside this subset. The inert strip-tag-prefix build
// extension is preserved without being used to infer a source version.
//
// Image and artifacts output sections are retained opaquely in the canonical
// base-input digest, not interpreted. They cannot establish output identity.
// Argument defaults are literal. Explicitly declared TARGETARCH, TARGETOS and
// TARGETPLATFORM arguments may have a null or empty default: their effective
// values come only from Metadata.Platform (linux/amd64 or linux/arm64). A matching
// literal default is accepted; a conflicting default, absent/unsupported target
// platform, undeclared variable, defaultless arbitrary argument, BUILD* platform
// argument or TARGETVARIANT is rejected. Builder-platform inference is unsupported.
// Null package constraints under root/target build, runtime or test dependencies
// mean unconstrained dependencies; they still leave dependency-identity evidence
// incomplete. Null tags and original values remain in the canonical base tree,
// distinct from empty string/map constraints, and recipe bytes are never rewritten.
// Every other null, including command/env/version/source identity fields, fails.
// The declaration/target-platform semantics follow Dalec v0.22.1 at
// https://github.com/project-dalec/dalec/tree/69b4357b942691ed9864cec73fd5785730232b69
// (frontend/build.go fillPlatformArgs, load.go SubstituteArgs, and deps.go
// PackageConstraints.UnmarshalYAML). No YAML node is replaced with a default.
// Other recipe strings, except the build commands described below, support only a single pass
// of ${ARG} expansion; unknown names, recursion, shell operators in substitutions,
// bare dollars and backticks are rejected. Inline patch contents are literal.
// Commands at build.steps[].command and targets.<name>.build.steps[].command
// are retained verbatim, matching Dalec's BuildStep.processBuildArgs, which
// expands step environments but never Command. Simple $NAME and ${NAME}
// runtime shell variables are supported without being evaluated or replaced.
// Builder-platform variables, parameter operators, command substitutions and
// backticks or eval remain unsupported. The command's original text and effective
// arguments/environments remain part of the base identity. The parser never
// executes commands or grants models permission to alter a trusted recipe.
//
// This matches load.go BuildStep.processBuildArgs and ArtifactBuild.processBuildArgs
// in the pinned Dalec versions; neither function substitutes Command.
//
// x-build-extensions.build-targets accepts a sequence of target names or a mapping
// from target names to {platforms: [os/arch[/variant], ...]}. Metadata must select
// the build target and platform explicitly; neither is guessed, even for a single
// choice. A target's exact override or its frontend namespace (before "/") can
// supply env overrides, but ambiguous overrides are rejected. Unselected targets,
// step environments, dependency constraints and commands remain in the base hash.
//
// # Digests and evidence
//
// ContentDigest and patch digests are sha256 of original bytes. BaseInputsDigest
// uses the versioned canonical encoding described at baseDigest and covers the
// entire resolved YAML tree except patch declarations and their inert local
// sources. Patch path, target source, strip and byte digest carry that excluded
// identity, along with InputDigest: sha256 of JSON fields domain, sourceName,
// kind, contextName, sourcePath and patchPath, in that order. Its domain is
// "orka.build-provenance.patch-input.v1"; kind is "context" or "inline". This
// prevents source renaming/remapping from hiding behind identical patch bytes.
// The base digest domain is orka.build-provenance.base.v2, superseding v1's
// command interpolation. Reacquire prior build bindings rather than reusing a
// v1 base digest after this change; comparisons never translate old receipts.
// All emitted digests and commits use lowercase hexadecimal. Image tags alone
// remain unverified. FrontendSyntax preserves the original syntax identity;
// Frontend is the effective immutable identity when known. Blank lines or
// ordinary comments end directive scanning. Missing or unpinned syntax is a
// missing requirement unless the caller supplies matching AttestedInputs; the
// parser never invents a pin or resolves a tag.
//
// # Caller-verified attestation inputs
//
// AttestedBuildInputs is a normalized caller contract, not a raw SLSA parser.
// The caller must first verify the statement, subject, signer and policy, then
// provide its sha256 StatementDigest, the observed published SubjectImageDigest,
// exact upstream repository/commit, named frontend/worker image identities and
// ConfigSource URI/path. ExpectedVersion and ExpectedRevision are mandatory on
// this path. The parser requires the subject to equal ObservedOriginalImage's
// explicit digest, the source to equal the selected Git source, and ConfigSource
// to name Metadata.Path. A frontend pin must match the syntax's image repository,
// any mutually supplied tag, and any syntax digest. A tag with an explicit
// attested digest is retained as name:tag@sha256:...; Worker is separately pinned.
// ErrAttestedInputsMismatch reports inconsistent or incomplete bindings.
//
// UpstreamCommitStatus becomes SourceAttested only through those caller-verified
// inputs. This does not attest the Git recipe commit. In particular,
// ConfigSource{URI: "input:context", Path: "..."} names supplied context content,
// not a Git recipe checkout, and never populates RecipeRepository/RecipeCommit.
// RecipeMappingStatus defaults to inferred when a recipe commit was supplied,
// otherwise unknown. MappingVerified requires an explicit caller assertion,
// exact recipe/image identities, expected version/revision, and a separate
// RecipeMappingEvidenceDigest; reusing the source statement digest is rejected.
// That mapping describes the original image's base Git recipe checkout, not a
// locally appended candidate overlay. Neither mapping nor source labels promote
// the overall evidence status or waive acquisition/build/image verification.
//
// ParseDalec always returns EvidencePartial with acquisition and image-binding
// gaps, even when all inputs and both image digests were supplied. Package/module
// dependency resolution is also a gap when declared. EvidenceVerified is reserved
// for a caller that independently verifies those external requirements. A
// published-image observation is never copied from a rebuilt-control observation.
// Neither semver, commit messages nor matching upstream commits prove equivalent
// downstream images.
//
// Compare requires identical complete base identities and no patch changes.
// CompareWithAdditionalPatch permits exactly one final caller-authorized patch
// digest, preserving all existing patch identities and the base recipe checkout.
// A candidate is a local overlay on that checkout, so its ContentDigest must
// change but its RecipeCommit must not. These functions compare records produced
// by the parser, including serialized records; they do not authenticate arbitrary
// caller-created digests or waive missing dependency/image attestations.
// Comparison also preserves frontend syntax, attested worker/frontend identities,
// context claims and independent mapping/source labels. It may compare inferred
// mappings for planning; success is not proof of a published-image recipe mapping.
//
// # Bounds and confidentiality
//
// Inputs are limited to MaxSpecBytes, MaxFiles, MaxFileBytes and MaxTotalBytes
// (the latter counts spec plus all supplied bytes). YAML depth, node count,
// scalars and metadata have additional bounds. Paths are canonical relative
// paths with no traversal, backslashes or .git components. Argument/environment
// keys identifying credentials, credential-bearing URLs, explicit credential
// assignments and private-key envelopes are rejected. This is not a general
// secret detector: the caller must provide only non-secret build variables and
// files. Errors never include raw YAML, private names, URLs, paths or values.
package provenance
