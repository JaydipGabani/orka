package supervisor

import "testing"

func TestSSETerminalErrorScannerDetectsInStreamFailures(t *testing.T) {
	t.Parallel()
	failures := []string{
		"event: message_start\ndata: {}\n\nevent: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n",
		"data: {\"type\":\"response.created\"}\n\ndata: {\"type\":\"response.failed\",\"response\":{}}\n\n",
		"data: {\"error\": {\"message\": \"rate limited\"}}\n\n",
	}
	for _, stream := range failures {
		scanner := &sseTerminalErrorScanner{}
		// Feed byte-by-byte to prove chunk boundaries cannot hide a marker.
		for i := 0; i < len(stream); i++ {
			if _, err := scanner.Write([]byte{stream[i]}); err != nil {
				t.Fatal(err)
			}
		}
		if !scanner.failed {
			t.Fatalf("scanner missed terminal error in %q", stream[:40])
		}
	}
	clean := []string{
		"event: message_start\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"discussing \\\"type\\\":\\\"error\\\" handling\"}}]}\n\ndata: [DONE]\n\n",
		"data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
	}
	for _, stream := range clean {
		scanner := &sseTerminalErrorScanner{}
		if _, err := scanner.Write([]byte(stream)); err != nil {
			t.Fatal(err)
		}
		if scanner.failed {
			t.Fatalf("scanner false-failed clean stream %q (detail %q)", stream[:40], scanner.detail)
		}
	}
}
