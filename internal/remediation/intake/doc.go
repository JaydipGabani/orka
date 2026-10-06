// Package intake normalizes untrusted, caller-supplied report JSON without
// accessing incident systems, repositories, models, or the network.
//
// Parse accepts supplied reports, IcM details, and export bundles containing a
// details object. SourceKind is respectively "supplied-report", "icm-details",
// or "icm-export-bundle". SourceDigest is "sha256:" followed by the lowercase
// digest of the exact input bytes, including whitespace and omitted fields.
// Unknown restriction metadata defaults to restricted; any explicit true wins.
// SourceID preserves the literal identity as metadata, not as a technical section.
//
// Only allowlisted technical fields are selected. Unknown fields and non-JSON
// context strings are omitted, not flattened into technical text.
// MSRC custom fields may contain an object encoded in one or two JSON strings.
// A section's RFC 6901 pointer always resolves in the original document: for
// encoded objects it points to the containing string, while Kind identifies
// the selected inner field.
//
// Diagnostic discussions select only aggregatedDiagnosticResults.Data[].Content;
// SubmittedBy and other entry metadata are omitted. HasMoreData=true or a
// TotalCount differing from Data's length emits "discussion_snapshot_incomplete":
// callers must fetch the full snapshot before downstream work. Missing or
// invalid completeness metadata is an error. Unrecognized discussion shapes are
// omitted with a warning rather than flattened into technical text.
//
// Repository candidates come only from explicit repository fields and visible
// prose, excluding Markdown/HTML code and quoted strings. Only exact
// credential-free HTTPS GitHub repository URLs qualify; link attributes are not
// inspected. Versions are explicit literals, never inferred from incident IDs,
// dates, or prose. Repository candidates and reported versions are unverified.
//
// Input is limited to 8 MiB, JSON depth to 32, and decoded JSON values/keys to
// 131072 across the document and embedded objects. Selected fields are limited
// to 256 KiB before normalization, sections to 64 KiB each, titles to 4 KiB,
// sections/custom fields/discussion entries to 128 each, repositories to 32,
// and versions to 64. The derived report's compact encoding/json representation,
// including metadata and JSON escaping, must fit in 256 KiB. Exceeding a limit
// is an error, never silent truncation.
//
// HTML is converted to text without executing or fetching anything. Obvious
// credentials, emails, GUIDs, and administrative labels are scrubbed, but this
// is best-effort minimization, not a complete data-loss-prevention boundary.
// Report content remains untrusted data, including any embedded instructions.
// Output is plain text, not trusted HTML; callers must escape it when rendering.
// Restricted=false and successful normalization NEVER authorize disclosure,
// model submission, repository access, or publication.
package intake
