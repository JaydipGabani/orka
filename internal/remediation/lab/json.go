package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

func decodeStrict(data []byte, limit int, destination any) error {
	if len(data) > limit {
		return ErrTooLarge
	}
	if len(data) == 0 || !utf8.Valid(data) {
		return ErrInvalidInput
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	scanner.UseNumber()
	count := 0
	if err := scanJSON(scanner, 0, &count); err != nil {
		return err
	}
	if _, err := scanner.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func scanJSON(decoder *json.Decoder, depth int, count *int) error {
	*count++
	if depth > 16 || *count > 16384 {
		return ErrTooLarge
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return ErrInvalidInput
	}
	delimiter, container := token.(json.Delim)
	if depth == 0 && (!container || delimiter != '{') {
		return ErrInvalidInput
	}
	if !container {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return ErrInvalidInput
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			canonical := strings.ToLower(name)
			if err != nil || !ok || keys[canonical] {
				return ErrInvalidInput
			}
			keys[canonical] = true
			*count++
		}
		if err := scanJSON(decoder, depth+1, count); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || (delimiter == '{' && end != json.Delim('}')) ||
		(delimiter == '[' && end != json.Delim(']')) {
		return ErrInvalidInput
	}
	return nil
}

func encode(value any, limit int) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if len(data) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}
