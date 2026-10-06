package environment

func bindExpectedObjects(receipt *Receipt, expectedObjects []ObjectIdentity) error {
	for _, expected := range expectedObjects {
		matched := false
		for i := range receipt.Objects {
			object := &receipt.Objects[i]
			if object.Kind != expected.Kind || object.Name != expected.Name || object.Namespace != expected.Namespace {
				continue
			}
			matched = true
			if expected.UID == "" || (object.UID != "" && object.UID != expected.UID) {
				return failure(Unknown, "expected-object-uid-mismatch")
			}
			object.UID = expected.UID
		}
		if !matched {
			return failure(Unknown, "expected-object-not-in-operation")
		}
	}
	return nil
}
