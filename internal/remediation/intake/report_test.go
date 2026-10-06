package intake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseSuppliedReports(t *testing.T) {
	t.Parallel()
	for _, repository := range []string{
		"https://github.com/fixture-org/go-widget",
		"https://github.com/fixture-org/c-parser",
		"https://github.com/Another-Fixture/http.service",
		"https://github.com/fixture-team/config_rules",
	} {
		t.Run(repository, func(t *testing.T) {
			data := marshalFixture(t, map[string]any{
				"title":       "Synthetic boundary handling",
				"problem":     "An empty input incorrectly succeeds.",
				"description": "Reject empty input before parsing.",
				"repository":  repository,
				"versions":    []string{"v1.2.3", "2.0.0-rc.1", "3.1.0+fixture"},
				"restricted":  false,
			})
			report := parseFixture(t, data)
			if report.Version != SchemaVersion || report.SourceKind != "supplied-report" ||
				report.Title != "Synthetic boundary handling" || report.Restricted {
				t.Fatal("supplied report metadata changed")
			}
			if !reflect.DeepEqual(report.Repositories, []string{repository}) ||
				!reflect.DeepEqual(report.Versions, []string{"v1.2.3", "2.0.0-rc.1", "3.1.0+fixture"}) {
				t.Fatal("explicit repository or version claims were lost")
			}
			for _, section := range []Section{
				{"title", "Synthetic boundary handling", "/title"},
				{"problem", "An empty input incorrectly succeeds.", "/problem"},
				{"description", "Reject empty input before parsing.", "/description"},
				{"repository-candidate", repository, "/repository"},
				{"reported-version", "v1.2.3", "/versions/0"},
			} {
				if !slices.Contains(report.Sections, section) {
					t.Fatal("missing technical section or provenance")
				}
			}
			assertWarning(t, report, "reported_versions_are_unverified")
			assertWarning(t, report, "normalization_does_not_authorize_disclosure")
			assertPointersResolve(t, data, report)
		})
	}
}

func TestParseIcMDetailsSelectsOnlyTechnicalFields(t *testing.T) {
	t.Parallel()
	data := marshalFixture(t, map[string]any{
		"id":           json.Number("900719925474099312345678901234567890"),
		"title":        "Synthetic parser incident",
		"summary":      "<p>An invalid length is accepted.</p><p>Validate the length first.</p>",
		"isRestricted": true,
		"customer":     "OMITTED_CUSTOMER_MARKER",
		"tenant":       "OMITTED_TENANT_MARKER",
		"contact":      "OMITTED_CONTACT_MARKER",
		"credentials":  "OMITTED_CREDENTIAL_MARKER",
		"customFields": []any{
			map[string]any{"Name": "Customer", "StringValue": `{"Title":"OMITTED_CUSTOMER_TITLE_MARKER"}`},
			map[string]any{"Name": "Tenant", "StringValue": "OMITTED_CUSTOM_FIELD_MARKER"},
			map[string]any{"Name": "RootCauseAnalysis", "StringValue": "The parser skips its bounds check."},
			map[string]any{"Name": "Recommended Resolution", "StringValue": "Reject an invalid length."},
		},
	})
	report := parseFixture(t, data)
	if report.SourceKind != "icm-details" || !report.Restricted ||
		report.SourceID != "900719925474099312345678901234567890" {
		t.Fatal("IcM identity or restriction metadata was not preserved")
	}
	assertNoMarker(t, report, "OMITTED_")
	if !slices.Contains(report.Sections, Section{"root-cause-analysis", "The parser skips its bounds check.", "/customFields/2/StringValue"}) ||
		!slices.Contains(report.Sections, Section{"recommended-resolution", "Reject an invalid length.", "/customFields/3/StringValue"}) {
		t.Fatal("direct technical custom field selection failed")
	}
	assertWarning(t, report, "nontechnical_fields_omitted")
	assertPointersResolve(t, data, report)
}

func TestParseMSRCEncodedFields(t *testing.T) {
	t.Parallel()
	for _, layers := range []int{1, 2} {
		t.Run(strconv.Itoa(layers), func(t *testing.T) {
			inner := string(marshalFixture(t, map[string]any{
				"Title":                 "Synthetic embedded report",
				"SecurityImpact":        "<p>Malformed input bypasses validation.</p>",
				"RootCauseAnalysis":     "The check is after parsing. See https://github.com/fixture-org/parser",
				"RecommendedResolution": "Validate before parsing; reported version v2.3.4 needs confirmation.",
				"Customer":              "OMITTED_INNER_CUSTOMER_MARKER",
				"Reporter":              "OMITTED_INNER_REPORTER_MARKER",
			}))
			if layers == 2 {
				inner = string(marshalFixture(t, inner))
			}
			data := marshalFixture(t, map[string]any{
				"id": "synthetic-incident",
				"customFields": []any{
					map[string]any{"Name": "MSRC Report", "StringValue": inner},
				},
			})
			report := parseFixture(t, data)
			if report.Title != "Synthetic embedded report" || len(report.Sections) != 5 {
				t.Fatal("embedded technical fields were not normalized")
			}
			for _, section := range report.Sections {
				if section.SourcePointer != "/customFields/0/StringValue" {
					t.Fatal("encoded object provenance must resolve to the original string")
				}
			}
			if !reflect.DeepEqual(report.Repositories, []string{"https://github.com/fixture-org/parser"}) {
				t.Fatal("visible repository reference was not discovered")
			}
			if len(report.Versions) != 0 {
				t.Fatal("a version was inferred from prose")
			}
			assertNoMarker(t, report, "OMITTED_")
			assertPointersResolve(t, data, report)
		})
	}
}

func TestParseMissingTechnicalDetailsIsExplicit(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		`{}`,
		`{"title":"Synthetic title only"}`,
		`{"title":"Synthetic empty body","summary":"<p> </p>"}`,
		`{"summary":"<script>hidden content</script>"}`,
		`{"problem":" ","customFields":[{"Name":"MSRC","StringValue":""}]}`,
		`{"details":{"title":"Synthetic metadata only"},"discussion":[{"text":"Do not select this"}]}`,
		`{"repository":"https://github.com/fixture-org/repo","versions":["1.2.3"]}`,
	} {
		report := parseFixture(t, []byte(source))
		assertWarning(t, report, "missing_technical_details")
		if report.Sections == nil {
			t.Fatal("sections must encode as an array, not null")
		}
	}
}

func TestParseBundle(t *testing.T) {
	t.Parallel()
	for _, encoding := range []string{"object", "string", "double-string", "unstructured"} {
		t.Run(encoding, func(t *testing.T) {
			context := any(map[string]any{
				"description": "A synthetic malformed length reproduces the problem.",
				"versions":    []string{"1.4.2"},
				"tenant":      "OMITTED_CONTEXT_TENANT_MARKER",
			})
			if encoding == "string" || encoding == "double-string" {
				context = string(marshalFixture(t, context))
			}
			if encoding == "double-string" {
				context = string(marshalFixture(t, context))
			}
			if encoding == "unstructured" {
				context = "OMITTED_UNSTRUCTURED_CONTEXT_MARKER"
			}
			data := marshalFixture(t, map[string]any{
				"details": map[string]any{
					"id": "synthetic-bundle", "title": "Synthetic bundle", "summary": "<p>Incorrect parsing.</p>",
					"isRestricted": false, "contact": "OMITTED_DETAILS_CONTACT_MARKER",
				},
				"context":    context,
				"discussion": []any{map[string]any{"text": "OMITTED_DISCUSSION_MARKER", "customer": "OMITTED_CUSTOMER_MARKER"}},
				"restricted": true,
			})
			report := parseFixture(t, data)
			if report.SourceKind != "icm-export-bundle" || report.SourceID != "synthetic-bundle" || !report.Restricted {
				t.Fatal("bundle metadata was not preserved")
			}
			if encoding == "unstructured" {
				assertWarning(t, report, "unstructured_context_omitted")
				if len(report.Versions) != 0 {
					t.Fatal("unstructured context was interpreted")
				}
			} else {
				expectedPointer := "/context"
				if encoding == "object" {
					expectedPointer += "/versions/0"
				}
				if !slices.Contains(report.Sections, Section{"reported-version", "1.4.2", expectedPointer}) {
					t.Fatal("bundle version provenance was lost")
				}
			}
			assertNoMarker(t, report, "OMITTED_")
			assertWarning(t, report, "discussion_omitted")
			assertPointersResolve(t, data, report)
		})
	}
}

func TestRestrictionDefaultsAndComposition(t *testing.T) {
	t.Parallel()
	for _, scenario := range []struct {
		source string
		want   bool
	}{
		{`{"problem":"Synthetic body"}`, true},
		{`{"problem":"Synthetic body","restricted":false}`, false},
		{`{"summary":"Synthetic body","restricted":false,"isRestricted":true}`, true},
		{`{"details":{"summary":"Synthetic body","isRestricted":true},"restricted":false}`, true},
		{`{"details":{"summary":"Synthetic body","isRestricted":false},"context":{"restricted":true}}`, true},
		{`{"details":{"summary":"Synthetic body"},"context":{"restricted":false}}`, true},
		{`{"details":{"summary":"Synthetic body","isRestricted":false},"context":{"restricted":false}}`, false},
	} {
		report := parseFixture(t, []byte(scenario.source))
		if report.Restricted != scenario.want {
			t.Fatal("restriction metadata was weakened")
		}
	}
}

func TestSourceIdentityAndExactByteDigest(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		`900719925474099312345678901234567890`,
		`-900719925474099312345678901234567890`,
		`-0.00`,
		`1e9999`,
		`"000123456789012345678901234567890"`,
		`"synthetic-incident-a"`,
	} {
		source := []byte(`{"id":` + id + `,"title":"Synthetic identity","summary":"Synthetic body"}`)
		report := parseFixture(t, source)
		if report.SourceID != strings.Trim(id, `"`) {
			t.Fatal("source identity lost its literal representation")
		}
		hash := sha256.Sum256(source)
		if report.SourceDigest != "sha256:"+hex.EncodeToString(hash[:]) {
			t.Fatal("source digest was not computed from exact input bytes")
		}
		spaced := parseFixture(t, append(bytes.Clone(source), ' '))
		if spaced.SourceDigest == report.SourceDigest {
			t.Fatal("whitespace changes must change the source digest")
		}
	}
	first := parseFixture(t, []byte(`{"problem":"Synthetic body","tenant":"omitted-a"}`))
	second := parseFixture(t, []byte(`{"problem":"Synthetic body","tenant":"omitted-b"}`))
	if first.SourceDigest == second.SourceDigest {
		t.Fatal("even omitted source fields must affect the digest")
	}
	first.SourceDigest, second.SourceDigest = "", ""
	if !reflect.DeepEqual(first, second) {
		t.Fatal("administrative values influenced normalized content")
	}
}

func TestParseRejectsInvalidSelectedShapesWithoutEcho(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		`{"details":"PRIVATE_ADMIN_VALUE"}`,
		`{"title":{"customer":"PRIVATE_ADMIN_VALUE"}}`,
		`{"problem":["PRIVATE_ADMIN_VALUE"]}`,
		`{"isRestricted":"PRIVATE_ADMIN_VALUE"}`,
		`{"restricted":null}`,
		`{"repository":{"credentials":"PRIVATE_ADMIN_VALUE"}}`,
		`{"versions":[{"tenant":"PRIVATE_ADMIN_VALUE"}]}`,
		`{"versions":["PRIVATE_ADMIN_VALUE"]}`,
		`{"id":{"customer":"PRIVATE_ADMIN_VALUE"}}`,
		`{"id":"PRIVATE_ADMIN_VALUE@example.invalid"}`,
		`{"customFields":{"customer":"PRIVATE_ADMIN_VALUE"}}`,
		`{"customFields":["PRIVATE_ADMIN_VALUE"]}`,
		`{"customFields":[{"Name":{"customer":"PRIVATE_ADMIN_VALUE"}}]}`,
		`{"customFields":[{"Name":"RootCauseAnalysis","StringValue":{"customer":"PRIVATE_ADMIN_VALUE"}}]}`,
		`{"customFields":[{"Name":"MSRC","StringValue":"PRIVATE_ADMIN_VALUE"}]}`,
		`{"details":{},"context":["PRIVATE_ADMIN_VALUE"]}`,
		`{"details":{},"context":"{\"customer\":\"PRIVATE_ADMIN_VALUE\",\"Title\":"}`,
		`{"versions":["1.2.3+11111111-2222-3333-4444-555555555555"]}`,
	} {
		report, err := Parse([]byte(source))
		if err == nil {
			t.Fatal("invalid selected field shape was accepted")
		}
		if strings.Contains(err.Error(), "PRIVATE_ADMIN_VALUE") || strings.Contains(err.Error(), "555555555555") {
			t.Fatal("error echoed caller-supplied administrative data")
		}
		if !reflect.DeepEqual(report, Report{}) {
			t.Fatal("failure returned a partial report")
		}
	}
}

func TestLimits(t *testing.T) {
	t.Parallel()
	t.Run("section exact boundary", func(t *testing.T) {
		report := parseFixture(t, marshalFixture(t, map[string]any{"problem": strings.Repeat("x", maxSectionBytes)}))
		if len(report.Sections[0].Text) != maxSectionBytes {
			t.Fatal("section at the exact limit was truncated")
		}
	})
	t.Run("input exact boundary", func(t *testing.T) {
		prefix, suffix := `{"problem":"Synthetic body","administration":"`, `"}`
		source := []byte(prefix + strings.Repeat("x", maxInputBytes-len(prefix)-len(suffix)) + suffix)
		parseFixture(t, source)
		if _, err := Parse(append(source, ' ')); err == nil {
			t.Fatal("input larger than 8 MiB was accepted")
		}
	})
	t.Run("title exact boundary", func(t *testing.T) {
		report := parseFixture(t, marshalFixture(t, map[string]any{"title": strings.Repeat("x", maxTitleBytes)}))
		if len(report.Title) != maxTitleBytes {
			t.Fatal("title at the exact limit was truncated")
		}
	})
	t.Run("raw field exact boundary", func(t *testing.T) {
		prefix, suffix := "<!--", "--><p>Synthetic</p>"
		raw := prefix + strings.Repeat("x", maxRawFieldBytes-len(prefix)-len(suffix)) + suffix
		report := parseFixture(t, marshalFixture(t, map[string]any{"summary": raw}))
		if !slices.Contains(report.Sections, Section{"summary", "Synthetic", "/summary"}) {
			t.Fatal("bounded HTML field did not retain its technical text")
		}
	})
	t.Run("derived JSON exact boundary", func(t *testing.T) {
		fields := make([]map[string]any, 4)
		for i := range fields {
			fields[i] = map[string]any{"Name": "RootCauseAnalysis", "StringValue": strings.Repeat("x", maxSectionBytes)}
		}
		fields[3]["StringValue"] = "x"
		source := map[string]any{"customFields": fields}
		base := parseFixture(t, marshalFixture(t, source))
		padding := maxDerivedBytes - len(marshalFixture(t, base))
		if padding < 1 || padding+2 > maxSectionBytes {
			t.Fatal("synthetic boundary fixture does not fit the section limits")
		}
		for _, delta := range []int{-1, 0, 1} {
			fields[3]["StringValue"] = strings.Repeat("x", padding+1+delta)
			report, err := Parse(marshalFixture(t, source))
			if delta > 0 {
				if err == nil || !reflect.DeepEqual(report, Report{}) {
					t.Fatal("one byte above the derived JSON limit did not fail without partial output")
				}
				continue
			}
			if err != nil {
				t.Fatalf("bounded derived report failed: %v", err)
			}
			if len(marshalFixture(t, report)) != maxDerivedBytes+delta {
				t.Fatal("derived report at the byte boundary was truncated or mismeasured")
			}
		}
	})
	t.Run("derived JSON escaping", func(t *testing.T) {
		source := marshalFixture(t, map[string]any{"problem": strings.Repeat("&", maxSectionBytes)})
		report, err := Parse(source)
		if err == nil || !reflect.DeepEqual(report, Report{}) {
			t.Fatal("JSON escape expansion bypassed the derived byte limit")
		}
	})
	t.Run("section count exact boundary", func(t *testing.T) {
		fields := make([]any, maxSections)
		for i := range fields {
			fields[i] = map[string]any{"Name": "RootCauseAnalysis", "StringValue": "Synthetic body"}
		}
		report := parseFixture(t, marshalFixture(t, map[string]any{"customFields": fields}))
		if len(report.Sections) != maxSections {
			t.Fatal("sections at the exact limit were dropped")
		}
	})
	t.Run("declaration counts exact boundary", func(t *testing.T) {
		versions := make([]string, maxVersions)
		for i := range versions {
			versions[i] = "1.2." + strconv.Itoa(i)
		}
		var body strings.Builder
		for i := range maxRepositories {
			body.WriteString("https://github.com/fixture-org/repo-" + strconv.Itoa(i) + "\n")
		}
		report := parseFixture(t, marshalFixture(t, map[string]any{"problem": body.String(), "versions": versions}))
		if len(report.Versions) != maxVersions || len(report.Repositories) != maxRepositories {
			t.Fatal("declarations at the exact count limits were dropped")
		}
	})
	for _, scenario := range []struct {
		name string
		data func() map[string]any
	}{
		{"title", func() map[string]any { return map[string]any{"title": strings.Repeat("x", maxTitleBytes+1)} }},
		{"section", func() map[string]any { return map[string]any{"problem": strings.Repeat("x", maxSectionBytes+1)} }},
		{"raw field", func() map[string]any { return map[string]any{"problem": strings.Repeat("x", maxRawFieldBytes+1)} }},
		{"context", func() map[string]any {
			return map[string]any{"details": map[string]any{}, "context": strings.Repeat("x", maxRawFieldBytes+1)}
		}},
		{"total text", func() map[string]any {
			fields := make([]any, 9)
			for i := range fields {
				fields[i] = map[string]any{"Name": "RootCauseAnalysis", "StringValue": strings.Repeat("x", maxSectionBytes)}
			}
			return map[string]any{"customFields": fields}
		}},
		{"sections", func() map[string]any {
			fields := make([]any, maxCustomFields)
			for i := range fields {
				fields[i] = map[string]any{"Name": "RootCauseAnalysis", "StringValue": "Synthetic body"}
			}
			return map[string]any{"title": "Synthetic title", "customFields": fields}
		}},
		{"custom fields", func() map[string]any {
			return map[string]any{"customFields": make([]any, maxCustomFields+1)}
		}},
		{"versions", func() map[string]any { return map[string]any{"versions": make([]string, maxVersions+1)} }},
		{"version literal", func() map[string]any {
			return map[string]any{"versions": "1.2.3+" + strings.Repeat("x", maxMetadataBytes)}
		}},
		{"repository literal", func() map[string]any {
			return map[string]any{"repository": strings.Repeat("x", maxMetadataBytes+1)}
		}},
		{"source ID", func() map[string]any { return map[string]any{"id": strings.Repeat("x", maxMetadataBytes+1)} }},
		{"repositories", func() map[string]any {
			var body strings.Builder
			for i := range maxRepositories + 1 {
				body.WriteString("https://github.com/fixture-org/repo-" + strconv.Itoa(i) + "\n")
			}
			return map[string]any{"problem": body.String()}
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := Parse(marshalFixture(t, scenario.data())); err == nil {
				t.Fatal("size or count limit silently accepted")
			}
		})
	}
}

func TestParseDeterministicAndWireShape(t *testing.T) {
	t.Parallel()
	source := []byte(`{"title":"Synthetic","problem":"Synthetic body","versions":"1.2.3","repository":"https://github.com/fixture-org/repo","customer":"omitted","tenant":"omitted"}`)
	first := parseFixture(t, source)
	for range 10 {
		if !reflect.DeepEqual(parseFixture(t, source), first) {
			t.Fatal("normalization is not deterministic")
		}
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(marshalFixture(t, first), &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "sourceKind", "sourceDigest", "restricted", "title", "sections", "repositories", "versions", "warnings"} {
		if _, exists := wire[key]; !exists {
			t.Fatal("required wire field is missing")
		}
	}
	if _, exists := wire["sourceID"]; exists {
		t.Fatal("empty optional source ID was emitted")
	}
}

func marshalFixture(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not marshal synthetic fixture")
	}
	return data
}

func parseFixture(t *testing.T, data []byte) Report {
	t.Helper()
	report, err := Parse(data)
	if err != nil {
		t.Fatalf("synthetic fixture failed: %v", err)
	}
	return report
}

func assertWarning(t *testing.T, report Report, warning string) {
	t.Helper()
	if !slices.Contains(report.Warnings, warning) {
		t.Fatalf("expected fixed warning %q", warning)
	}
}

func assertNoMarker(t *testing.T, report Report, marker string) {
	t.Helper()
	if strings.Contains(string(marshalFixture(t, report)), marker) {
		t.Fatal("normalized report leaked an omitted synthetic marker")
	}
}

func assertPointersResolve(t *testing.T, data []byte, report Report) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		t.Fatal("could not decode synthetic fixture for provenance checks")
	}
	for _, section := range report.Sections {
		value := root
		if !strings.HasPrefix(section.SourcePointer, "/") {
			t.Fatal("section has no original JSON pointer")
		}
		for token := range strings.SplitSeq(section.SourcePointer[1:], "/") {
			token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
			switch current := value.(type) {
			case map[string]any:
				var exists bool
				value, exists = current[token]
				if !exists {
					t.Fatal("source pointer does not resolve to an original field")
				}
			case []any:
				index, err := strconv.Atoi(token)
				if err != nil || index < 0 || index >= len(current) {
					t.Fatal("source pointer does not resolve to an original array entry")
				}
				value = current[index]
			default:
				t.Fatal("source pointer invents a path inside a scalar")
			}
		}
		if _, ok := value.(string); !ok {
			t.Fatal("technical section provenance is not an original string")
		}
	}
}
