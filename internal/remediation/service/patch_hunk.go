package service

import (
	"regexp"
	"strconv"
)

var patchHunkPattern = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?:.*)$`)

type patchHunk struct{ original, patched int }

func (h patchHunk) active() bool { return h.original != 0 || h.patched != 0 }

func parsePatchHunk(line string) (patchHunk, error) {
	match := patchHunkPattern.FindStringSubmatch(line)
	if match == nil {
		return patchHunk{}, ErrInvalid
	}
	var values [4]int
	for i := range values {
		text := match[i+1]
		if text == "" {
			text = "1"
		}
		value, err := strconv.ParseUint(text, 10, 32)
		if err != nil || value > MaxPatchBytes {
			return patchHunk{}, ErrInvalid
		}
		values[i] = int(value)
	}
	return patchHunk{original: values[1], patched: values[3]}, nil
}

func (h *patchHunk) consume(line string) error {
	if line == `\ No newline at end of file` {
		return nil
	}
	if line == "" {
		return ErrInvalid
	}
	switch line[0] {
	case ' ':
		h.original--
		h.patched--
	case '-':
		h.original--
	case '+':
		h.patched--
	default:
		return ErrInvalid
	}
	if h.original < 0 || h.patched < 0 {
		return ErrInvalid
	}
	return nil
}
