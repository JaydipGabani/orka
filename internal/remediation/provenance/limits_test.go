package provenance

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestParseDalecByteLimits(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{MaxSpecBytes - 1, MaxSpecBytes, MaxSpecBytes + 1} {
		t.Run(fmt.Sprintf("spec-%d", limit), func(t *testing.T) {
			input := fixture(t)
			input.spec = append(input.spec, '#')
			input.spec = append(input.spec, bytes.Repeat([]byte("x"), limit-len(input.spec))...)
			input.files[input.metadata.Path] = bytes.Clone(input.spec)
			if limit > MaxSpecBytes {
				requireParseError(t, input)
			} else {
				input.parse(t)
			}
		})
	}
	for _, limit := range []int{MaxFileBytes - 1, MaxFileBytes, MaxFileBytes + 1} {
		t.Run(fmt.Sprintf("patch-%d", limit), func(t *testing.T) {
			input := fixture(t)
			input.files["patches/0001-vendor.patch"] = bytes.Repeat([]byte("x"), limit)
			if limit > MaxFileBytes {
				requireParseError(t, input)
			} else {
				input.parse(t)
			}
		})
	}
}

func TestParseDalecAggregateLimit(t *testing.T) {
	t.Parallel()
	for _, total := range []int{MaxTotalBytes - 1, MaxTotalBytes, MaxTotalBytes + 1} {
		t.Run(fmt.Sprintf("total-%d", total), func(t *testing.T) {
			input := fixture(t)
			input.appendPatch(t, "0003-extra.patch", []byte("patch\n"))
			input.appendPatch(t, "0004-extra.patch", []byte("patch\n"))
			for _, name := range []string{"patches/0001-vendor.patch", "patches/0002-vendor.patch", "patches/0003-extra.patch"} {
				input.files[name] = bytes.Repeat([]byte("x"), MaxFileBytes)
			}
			remainder := total - 2*len(input.spec) - 3*MaxFileBytes
			input.files["patches/0004-extra.patch"] = bytes.Repeat([]byte("x"), remainder)
			if total > MaxTotalBytes {
				requireParseError(t, input)
			} else {
				input.parse(t)
			}
		})
	}
}

func TestParseDalecFileCountLimit(t *testing.T) {
	t.Parallel()
	for _, count := range []int{MaxFiles - 1, MaxFiles, MaxFiles + 1} {
		t.Run(fmt.Sprintf("files-%d", count), func(t *testing.T) {
			input := fixture(t)
			var entries strings.Builder
			for index := 3; index < count; index++ {
				name := fmt.Sprintf("extra-%03d.patch", index)
				fmt.Fprintf(&entries, "    - source: vendor-patches\n      path: %s\n", name)
				input.files["patches/"+name] = []byte("inert patch bytes\n")
			}
			input.replace(t, "\nbuild:\n", "\n"+entries.String()+"build:\n")
			if len(input.files) != count {
				t.Fatal("file count fixture does not exercise the stated limit")
			}
			if count > MaxFiles {
				requireParseError(t, input)
			} else {
				input.parse(t)
			}
		})
	}
}

func TestParseDalecStructuralLimits(t *testing.T) {
	t.Parallel()
	for _, count := range []int{maxScalarSize - 1, maxScalarSize, maxScalarSize + 1} {
		t.Run(fmt.Sprintf("scalar-%d", count), func(t *testing.T) {
			input := fixture(t)
			input.replace(t, "Synthetic downstream component", strings.Repeat("x", count))
			if count > maxScalarSize {
				requireParseError(t, input)
			} else {
				input.parse(t)
			}
		})
	}
	input := fixture(t)
	input.replace(t, "name: engine", "artifacts: "+strings.Repeat("[", maxYAMLDepth)+"x"+strings.Repeat("]", maxYAMLDepth)+"\nname: engine")
	requireParseError(t, input)
	input = fixture(t)
	input.replace(t, "name: engine", "artifacts: ["+strings.Repeat("x,", maxYAMLNodes)+"]\nname: engine")
	requireParseError(t, input)
	input = fixture(t)
	input.replace(t, "  REVISION: \"2\"", "  REVISION: \"2\"\n  EXPANSION: \""+strings.Repeat("x", maxValueSize)+"\"")
	var expanded strings.Builder
	expanded.WriteString("artifacts:\n")
	for index := range 17 {
		fmt.Fprintf(&expanded, "  key%d: \"%s\"\n", index, strings.Repeat("${EXPANSION}", 16))
	}
	input.replace(t, "name: engine", expanded.String()+"name: engine")
	requireParseError(t, input)
}

func FuzzParseDalec(f *testing.F) {
	seed := fixtureForFuzz()
	f.Add(seed)
	f.Add([]byte("name: broken\nname: duplicate\n"))
	f.Add([]byte("sources: &ref {value: *ref}\n"))
	f.Fuzz(func(t *testing.T, spec []byte) {
		if len(spec) > MaxSpecBytes {
			return
		}
		files := map[string][]byte{"recipe.yml": bytes.Clone(spec)}
		recipe, err := ParseDalec(spec, files, Metadata{Path: "recipe.yml"})
		if err == nil && (recipe.EvidenceStatus != EvidencePartial || recipe.ContentDigest != expectedDigest(spec) || len(recipe.Missing) == 0) {
			t.Fatal("successful parse lost byte identity or claimed complete provenance")
		}
	})
}

func fixtureForFuzz() []byte {
	return []byte("name: synthetic\nversion: '1.0.0'\nrevision: '1'\nsources:\n  component:\n    git:\n      url: https://example.invalid/component/repo\n      commit: '" +
		strings.Repeat("a", 40) + "'\n")
}
