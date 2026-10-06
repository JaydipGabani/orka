package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/orka-agents/orka/internal/redact"
)

const SchemaVersion = 1

type Section struct {
	Kind          string `json:"kind"`
	Text          string `json:"text"`
	SourcePointer string `json:"sourcePointer"`
}

type Report struct {
	Version      int       `json:"version"`
	SourceKind   string    `json:"sourceKind"`
	SourceID     string    `json:"sourceID,omitempty"`
	SourceDigest string    `json:"sourceDigest"`
	Restricted   bool      `json:"restricted"`
	Title        string    `json:"title"`
	Sections     []Section `json:"sections"`
	Repositories []string  `json:"repositories,omitempty"`
	Versions     []string  `json:"versions,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
}

const (
	maxDerivedBytes   = 256 << 10
	maxRawFieldBytes  = 256 << 10
	maxSectionBytes   = 64 << 10
	maxTotalTextBytes = maxDerivedBytes
	maxTitleBytes     = 4 << 10
	maxSections       = 128
	maxCustomFields   = 128
	maxRepositories   = 32
	maxVersions       = 64
	maxMetadataBytes  = 256
)

const (
	titleField                     = "title"
	problemField                   = "problem"
	descriptionField               = "description"
	summaryField                   = "summary"
	restrictedField                = "restricted"
	msrcTitleField                 = "Title"
	msrcSecurityImpactField        = "SecurityImpact"
	msrcRootCauseAnalysisField     = "RootCauseAnalysis"
	msrcRecommendedResolutionField = "RecommendedResolution"
	icmRestrictedField             = "isRestricted"
)

var (
	sourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]*$`)
	versionPattern  = regexp.MustCompile(`^[vV]?[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$`)
)

type technicalField struct {
	key  string
	kind string
}

var commonFields = []technicalField{
	{titleField, titleField},
	{problemField, problemField},
	{descriptionField, descriptionField},
	{summaryField, summaryField},
}

var msrcFields = []technicalField{
	{msrcTitleField, titleField},
	{msrcSecurityImpactField, "security-impact"},
	{msrcRootCauseAnalysisField, "root-cause-analysis"},
	{msrcRecommendedResolutionField, "recommended-resolution"},
}

type normalizer struct {
	report          Report
	budget          jsonBudget
	textBytes       int
	technicalBody   bool
	restrictionSeen bool
}

// Parse treats all input, including incident instructions, as untrusted data.
// Errors and warnings contain no caller-supplied names or values. An error
// always returns a zero Report rather than a partially normalized document.
func Parse(data []byte) (Report, error) {
	n := normalizer{}
	value, err := decodeJSON(data, &n.budget)
	if err != nil {
		return Report{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Report{}, errors.New("report must be a JSON object")
	}
	digest := sha256.Sum256(data)
	n.report = Report{
		Version:      SchemaVersion,
		SourceKind:   "supplied-report",
		SourceDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Sections:     make([]Section, 0),
	}
	n.warn("report_content_is_untrusted_data")
	n.warn("normalization_does_not_authorize_disclosure")
	if details, bundle := object["details"]; bundle {
		n.report.SourceKind = "icm-export-bundle"
		details, ok := details.(map[string]any)
		if !ok {
			return Report{}, errors.New("export bundle details must be an object")
		}
		if err := n.restriction(object, true); err != nil {
			return Report{}, err
		}
		if err := n.details(details, "/details"); err != nil {
			return Report{}, err
		}
		if context, exists := object["context"]; exists {
			if err := n.context(context); err != nil {
				return Report{}, err
			}
		}
		if discussion, exists := object["discussion"]; exists {
			if err := n.discussion(discussion); err != nil {
				return Report{}, err
			}
		}
		n.omittedFields(object, []string{"details", "context", "discussion", restrictedField, icmRestrictedField})
	} else {
		for _, key := range []string{"id", summaryField, icmRestrictedField, "customFields"} {
			if _, exists := object[key]; exists {
				n.report.SourceKind = "icm-details"
			}
		}
		if err := n.details(object, ""); err != nil {
			return Report{}, err
		}
	}
	if !n.restrictionSeen {
		n.report.Restricted = true
		n.warn("restriction_unspecified_assumed_restricted")
	}
	if n.report.Title == "" {
		n.warn("missing_title")
	}
	if !n.technicalBody {
		n.warn("missing_technical_details")
	}
	encoded, err := json.Marshal(n.report)
	if err != nil {
		return Report{}, errors.New("could not encode normalized report")
	}
	if len(encoded) > maxDerivedBytes {
		return Report{}, errors.New("normalized report exceeds the 256 KiB derived JSON limit")
	}
	return n.report, nil
}

func (n *normalizer) details(object map[string]any, base string) error {
	if err := n.restriction(object, true); err != nil {
		return err
	}
	if id, exists := object["id"]; exists {
		var literal string
		valid := false
		switch id := id.(type) {
		case string:
			literal = id
			valid = len(literal) <= maxMetadataBytes && sourceIDPattern.MatchString(literal) &&
				redact.SensitiveText(literal) == literal
		case json.Number:
			literal = id.String()
			valid = true
		default:
			return errors.New("source id must be a string or JSON number")
		}
		if len(literal) == 0 || len(literal) > maxMetadataBytes || !valid {
			return errors.New("source id must be a plain identifier of at most 256 bytes")
		}
		n.report.SourceID = literal
	}
	if err := n.fields(object, base, false, commonFields); err != nil {
		return err
	}
	if err := n.declarations(object, base, false); err != nil {
		return err
	}
	if custom, exists := object["customFields"]; exists {
		if err := n.customFields(custom, pointer(base, "customFields", false)); err != nil {
			return err
		}
	}
	n.omittedFields(object, []string{
		"id", titleField, problemField, descriptionField, summaryField, "repository", "versions",
		restrictedField, icmRestrictedField, "customFields",
	})
	return nil
}

func (n *normalizer) restriction(object map[string]any, authoritative bool) error {
	for _, key := range []string{restrictedField, icmRestrictedField} {
		if value, exists := object[key]; exists {
			restricted, ok := value.(bool)
			if !ok {
				return errors.New("restriction fields must be booleans")
			}
			n.restrictionSeen = n.restrictionSeen || authoritative
			n.report.Restricted = n.report.Restricted || restricted
		}
	}
	return nil
}

func (n *normalizer) fields(object map[string]any, base string, encoded bool, fields []technicalField) error {
	for _, field := range fields {
		if value, exists := object[field.key]; exists {
			text, ok := value.(string)
			if !ok {
				return errors.New("selected technical fields must be strings")
			}
			if err := n.technical(field.kind, text, pointer(base, field.key, encoded)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *normalizer) declarations(object map[string]any, base string, encoded bool) error {
	if value, exists := object["repository"]; exists {
		repository, ok := value.(string)
		if !ok {
			return errors.New("repository must be a string")
		}
		if len(repository) > maxMetadataBytes {
			return errors.New("repository exceeds the 256 byte limit")
		}
		if !canonicalRepository(repository) {
			n.warn("noncanonical_repository_omitted")
		} else if err := n.repository(repository, pointer(base, "repository", encoded)); err != nil {
			return err
		}
	}
	if value, exists := object["versions"]; exists {
		if err := n.versions(value, pointer(base, "versions", encoded), encoded); err != nil {
			return err
		}
	}
	return nil
}

func (n *normalizer) customFields(value any, base string) error {
	fields, ok := value.([]any)
	if !ok {
		return errors.New("customFields must be an array")
	}
	if len(fields) > maxCustomFields {
		return errors.New("customFields exceeds the 128 field limit")
	}
	for i, value := range fields {
		field, ok := value.(map[string]any)
		if !ok {
			return errors.New("customFields entries must be objects")
		}
		n.omittedFields(field, []string{"Name", "StringValue"})
		name, ok := field["Name"].(string)
		if !ok || len(name) > maxMetadataBytes {
			return errors.New("custom field Name must be a string of at most 256 bytes")
		}
		canonical := strings.NewReplacer(" ", "", "_", "", "-", "").Replace(strings.ToLower(name))
		kind := ""
		for _, technical := range msrcFields {
			if canonical == strings.ToLower(technical.key) {
				kind = technical.kind
			}
		}
		embedded := slices.Contains([]string{
			"msrc", "msrcfields", "msrcreport", "msrcdata", "msrcdetails", "msrcinfo", "msrcinformation", "msrcreportdata",
		}, canonical)
		if kind == "" && !embedded {
			n.warn("nontechnical_fields_omitted")
			continue
		}
		text, ok := field["StringValue"].(string)
		if !ok {
			return errors.New("selected custom field StringValue must be a string")
		}
		if len(text) > maxRawFieldBytes {
			return errors.New("selected custom field exceeds the 256 KiB limit")
		}
		source := pointer(pointer(base, strconv.Itoa(i), false), "StringValue", false)
		if !embedded {
			if err := n.technical(kind, text, source); err != nil {
				return err
			}
			continue
		}
		if strings.TrimSpace(text) == "" {
			n.warn("empty_technical_field_omitted")
			continue
		}
		object, err := decodeEmbeddedObject(text, &n.budget)
		if err != nil {
			return err
		}
		if err := n.fields(object, source, true, msrcFields); err != nil {
			return err
		}
		n.omittedFields(object, []string{
			msrcTitleField, msrcSecurityImpactField, msrcRootCauseAnalysisField, msrcRecommendedResolutionField,
		})
	}
	return nil
}

func (n *normalizer) context(value any) error {
	encoded := false
	var object map[string]any
	switch value := value.(type) {
	case map[string]any:
		object = value
	case string:
		if len(value) > maxRawFieldBytes {
			return errors.New("export context exceeds the 256 KiB limit")
		}
		trimmed := strings.TrimSpace(value)
		if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "\"") {
			n.warn("unstructured_context_omitted")
			return nil
		}
		var err error
		object, err = decodeEmbeddedObject(value, &n.budget)
		if err != nil {
			return err
		}
		encoded = true
	default:
		return errors.New("export context must be an object or string")
	}
	if err := n.restriction(object, false); err != nil {
		return err
	}
	for _, fields := range [][]technicalField{commonFields, msrcFields} {
		if err := n.fields(object, "/context", encoded, fields); err != nil {
			return err
		}
	}
	if err := n.declarations(object, "/context", encoded); err != nil {
		return err
	}
	n.omittedFields(object, []string{
		titleField, problemField, descriptionField, summaryField, msrcTitleField, msrcSecurityImpactField,
		msrcRootCauseAnalysisField, msrcRecommendedResolutionField, "repository", "versions", restrictedField, icmRestrictedField,
	})
	return nil
}

func (n *normalizer) discussion(value any) error {
	discussion, ok := value.(map[string]any)
	if !ok {
		n.warn("discussion_omitted")
		return nil
	}
	value, exists := discussion["aggregatedDiagnosticResults"]
	if !exists {
		n.warn("discussion_omitted")
		return nil
	}
	aggregate, ok := value.(map[string]any)
	if !ok {
		return errors.New("discussion aggregatedDiagnosticResults must be an object")
	}
	entries, ok := aggregate["Data"].([]any)
	if !ok {
		return errors.New("diagnostic discussion Data must be an array")
	}
	if len(entries) > maxSections {
		return errors.New("diagnostic discussion exceeds the 128 entry limit")
	}
	more, ok := aggregate["HasMoreData"].(bool)
	if !ok {
		return errors.New("diagnostic discussion HasMoreData must be a boolean")
	}
	number, ok := aggregate["TotalCount"].(json.Number)
	if !ok {
		return errors.New("diagnostic discussion TotalCount must be a nonnegative integer literal")
	}
	total, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return errors.New("diagnostic discussion TotalCount must be a nonnegative integer literal fitting 64 bits")
	}
	if more || total != uint64(len(entries)) {
		n.warn("discussion_snapshot_incomplete")
	}
	n.omittedFields(discussion, []string{"aggregatedDiagnosticResults"})
	n.omittedFields(aggregate, []string{"Data", "HasMoreData", "TotalCount"})
	for i, value := range entries {
		entry, ok := value.(map[string]any)
		if !ok {
			return errors.New("diagnostic discussion entries must be objects")
		}
		content, ok := entry["Content"].(string)
		if !ok {
			return errors.New("diagnostic discussion entries require string Content")
		}
		n.omittedFields(entry, []string{"Content"})
		source := pointer(pointer("/discussion/aggregatedDiagnosticResults/Data", strconv.Itoa(i), false), "Content", false)
		if err := n.technical("discussion", content, source); err != nil {
			return err
		}
	}
	return nil
}

func (n *normalizer) technical(kind, raw, source string) error {
	if len(raw) > maxRawFieldBytes {
		return errors.New("selected technical field exceeds the 256 KiB limit")
	}
	if kind == titleField && len(raw) > maxTitleBytes {
		return errors.New("title exceeds the 4 KiB limit")
	}
	text, prose, flags, err := normalizeText(raw)
	if err != nil {
		return err
	}
	for _, flag := range flags {
		n.warn(flag)
	}
	if text == "" {
		n.warn("empty_technical_field_omitted")
		return nil
	}
	if kind == titleField {
		if len(text) > maxTitleBytes {
			return errors.New("normalized title exceeds the 4 KiB limit")
		}
		if n.report.Title == "" {
			n.report.Title = text
		}
	} else if strings.TrimSpace(strings.ReplaceAll(text, redactionMarker, "")) != "" {
		n.technicalBody = true
	}
	if err := n.section(kind, text, source); err != nil {
		return err
	}
	if kind != titleField {
		for _, candidate := range urlPattern.FindAllString(proseWithoutCode(prose), -1) {
			candidate = trimURLPunctuation(candidate)
			if canonicalRepository(candidate) {
				if err := n.repository(candidate, source); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (n *normalizer) repository(repository, source string) error {
	if !slices.ContainsFunc(n.report.Repositories, func(existing string) bool {
		return strings.EqualFold(existing, repository)
	}) {
		if len(n.report.Repositories) >= maxRepositories {
			return errors.New("report exceeds the 32 repository limit")
		}
		n.report.Repositories = append(n.report.Repositories, repository)
	}
	n.warn("repository_candidates_are_unverified")
	return n.section("repository-candidate", repository, source)
}

func (n *normalizer) versions(value any, source string, encoded bool) error {
	var values []any
	array := false
	switch value := value.(type) {
	case string:
		values = []any{value}
	case []any:
		values = value
		array = true
	default:
		return errors.New("versions must be a string or array of strings")
	}
	if len(values) > maxVersions {
		return errors.New("report exceeds the 64 version limit")
	}
	for i, value := range values {
		version, ok := value.(string)
		if !ok || len(version) > maxMetadataBytes || !versionPattern.MatchString(version) {
			return errors.New("versions entries must be explicit version literals of at most 256 bytes")
		}
		if scrubText(version) != version {
			return errors.New("version literals must not contain sensitive text")
		}
		if !slices.Contains(n.report.Versions, version) {
			if len(n.report.Versions) >= maxVersions {
				return errors.New("report exceeds the 64 version limit")
			}
			n.report.Versions = append(n.report.Versions, version)
		}
		entrySource := source
		if array && !encoded {
			entrySource = pointer(source, strconv.Itoa(i), false)
		}
		if err := n.section("reported-version", version, entrySource); err != nil {
			return err
		}
		n.warn("reported_versions_are_unverified")
	}
	return nil
}

func (n *normalizer) section(kind, text, source string) error {
	section := Section{Kind: kind, Text: text, SourcePointer: source}
	if slices.Contains(n.report.Sections, section) {
		return nil
	}
	if len(text) > maxSectionBytes {
		return errors.New("normalized section exceeds the 64 KiB text limit")
	}
	if len(n.report.Sections) >= maxSections {
		return errors.New("report exceeds the 128 section limit")
	}
	if n.textBytes+len(text) > maxTotalTextBytes {
		return errors.New("report exceeds the 256 KiB total text limit")
	}
	n.textBytes += len(text)
	n.report.Sections = append(n.report.Sections, section)
	return nil
}

func (n *normalizer) warn(warning string) {
	if !slices.Contains(n.report.Warnings, warning) {
		n.report.Warnings = append(n.report.Warnings, warning)
	}
}

func (n *normalizer) omittedFields(object map[string]any, allowed []string) {
	for key := range object {
		if !slices.Contains(allowed, key) {
			n.warn("nontechnical_fields_omitted")
			return
		}
	}
}

func pointer(base, token string, encoded bool) string {
	if encoded {
		return base
	}
	token = strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
	return base + "/" + token
}
