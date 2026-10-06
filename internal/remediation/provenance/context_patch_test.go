package provenance

import "testing"

func TestContextPatchRequiresDirectorySubpath(t *testing.T) {
	input := fixture(t)
	input.replace(t, "      path: 0001-vendor.patch\n", "")
	requireParseError(t, input)
}
