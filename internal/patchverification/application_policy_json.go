package patchverification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Missing scope must not become newly admitted cluster authority through Go's
// zero bool value. The ordinary wire format still includes the existing field.
func (rule *ApplicationResourceRule) UnmarshalJSON(content []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(content, &fields) != nil {
		return ErrEvidence
	}

	scope, present := fields["namespaced"]
	if !present || bytes.Equal(bytes.TrimSpace(scope), []byte("null")) {
		return errors.New("application resource rules require an explicit namespaced boolean")
	}
	type plain ApplicationResourceRule
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrEvidence
	}
	*rule = ApplicationResourceRule(decoded)
	return nil
}

func (qualification *ApplicationRuntimeQualification) UnmarshalJSON(content []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(content, &fields) != nil {
		return ErrEvidence
	}
	swap, present := fields["nativeSwapMax"]
	if !present || bytes.Equal(bytes.TrimSpace(swap), []byte("null")) {
		return errors.New("application runtime qualification requires explicit native no-swap evidence")
	}
	type plain ApplicationRuntimeQualification
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrEvidence
	}
	*qualification = ApplicationRuntimeQualification(decoded)
	return nil
}
