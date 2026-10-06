//go:build patchverify_fixture

package order

import "testing"

func TestNormal(test *testing.T) {
	if !Accept(5) {
		test.Fatal("POC assertion failed")
	}
}

func TestLow(test *testing.T) {
	if Accept(-1) {
		test.Fatal("POC assertion failed")
	}
}

func TestHigh(test *testing.T) {
	if Accept(101) {
		test.Fatal("POC assertion failed")
	}
}
