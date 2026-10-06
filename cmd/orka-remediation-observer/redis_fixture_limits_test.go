package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRedisFixtureRetainsExactByteBudget(t *testing.T) {
	key := "synthetic-list-" + syntheticValue()
	frame := respFrame("EVAL", publicRedisListLengthScript, "1", key)
	for _, limit := range []int{len(frame) - 1, len(frame), len(frame) + 1} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			length := 0
			f := startTestObserver(t, func(cfg *config) {
				cfg.RedisFixtureQueueLength = &length
				cfg.RedisFixtureListKeySHA256 = wireDigest(key)
				cfg.Limits.RESPBytes = limit
				cfg.Limits.RESPCommands = 1
			})
			conn := dialTest(t, f.config.RESPAddress)
			sendWire(t, conn, frame)
			want, count := ":0\r\n", 1
			if limit < len(frame) {
				want, count = "-ERR malformed frame\r\n", 0
			}
			requireWire(t, conn, want)
			requireClosed(t, conn)
			state := f.state(t)
			if len(state.RESP) != count || state.DroppedRESP != 0 {
				t.Fatal("script frames bypassed the existing encoded-byte budget")
			}
			if count == 1 && !state.RESP[0].MetricQueryMatched {
				t.Fatal("a complete exact-budget metric query lost its typed match flag")
			}
		})
	}
}

func TestRedisFixtureRetainsCommandAndRecordBudgets(t *testing.T) {
	t.Run("commands", func(t *testing.T) {
		f, key := startRedisFixture(t, 0, func(cfg *config) { cfg.Limits.RESPCommands = 2 })
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, strings.Repeat(respFrame("LLEN", key), 3))
		requireWire(t, conn, ":0\r\n:0\r\n")
		if len(requireClosed(t, conn)) != 0 || len(f.state(t).RESP) != 2 {
			t.Fatal("fixed integer replies exceeded the connection command cap")
		}
	})
	t.Run("records", func(t *testing.T) {
		f, key := startRedisFixture(t, 0, func(cfg *config) { cfg.Limits.RESPObservations = 2 })
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, strings.Repeat(respFrame("EVAL", publicRedisListLengthScript, "1", key), 5))
		requireWire(t, conn, strings.Repeat(":0\r\n", 5))
		state := f.state(t)
		if len(state.RESP) != 2 || state.DroppedRESP != 3 {
			t.Fatal("metric-query evidence escaped its existing observation quota")
		}
	})
	t.Run("arguments", func(t *testing.T) {
		f, key := startRedisFixture(t, 0, nil)
		conn := dialTest(t, f.config.RESPAddress)
		args := make([]string, 17)
		copy(args, []string{"EVAL", publicRedisListLengthScript, "1", key})
		sendWire(t, conn, respFrame(args...))
		requireWire(t, conn, "-ERR malformed frame\r\n")
		requireClosed(t, conn)
		if len(f.state(t).RESP) != 0 {
			t.Fatal("metric support raised the existing sixteen-argument frame cap")
		}
	})
}

func TestRedisFixtureResetFencesMatchedQueries(t *testing.T) {
	f, key := startRedisFixture(t, 0, nil)
	conn := dialTest(t, f.config.RESPAddress)
	query := respFrame("EVAL", publicRedisListLengthScript, "1", key)
	sendWire(t, conn, query)
	requireWire(t, conn, ":0\r\n")
	response := f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil)
	requireStatus(t, response, http.StatusOK)
	sendWire(t, conn, query)
	requireWire(t, conn, ":0\r\n")
	state := f.state(t)
	if state.Generation != 2 || len(state.RESP) != 0 {
		t.Fatal("old-connection metric flags crossed the administrative generation reset")
	}
	fresh := dialTest(t, f.config.RESPAddress)
	sendWire(t, fresh, respFrame("AUTH", f.canary)+query)
	requireWire(t, fresh, "+OK\r\n:0\r\n")
	state = f.state(t)
	if len(state.RESP) != 2 || !state.RESP[0].SyntheticCredentialObserved || !state.RESP[1].MetricQueryMatched {
		t.Fatal("fresh credential and metric controls failed after reset fencing")
	}
	var request map[string]any
	if err := json.Unmarshal(resetBody(f.config.RunID, 2), &request); err != nil {
		t.Fatal("encode synthetic reset control")
	}
	request["redisFixtureQueueLength"] = 10
	request["metricQueryMatched"] = true
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal("encode untrusted reset fields")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, body, nil), http.StatusBadRequest)
	sendWire(t, fresh, query)
	requireWire(t, fresh, ":0\r\n")
	if f.state(t).Generation != 2 {
		t.Fatal("reset input mutated immutable operator fixture configuration")
	}
}

func TestRedisFixtureSlowFrameAndShutdownRemainBounded(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		f, key := startRedisFixture(t, 0, func(cfg *config) { cfg.Limits.RESPReadTimeoutMillis = 150 })
		frame := respFrame("EVAL", publicRedisListLengthScript, "1", key)
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, frame[:len(frame)-1])
		start := time.Now()
		requireClosed(t, conn)
		if time.Since(start) > time.Second || len(f.state(t).RESP) != 0 {
			t.Fatal("incomplete script frame escaped the read deadline or produced success evidence")
		}
	})
	t.Run("shutdown", func(t *testing.T) {
		f, key := startRedisFixture(t, 0, func(cfg *config) {
			cfg.Limits.RESPReadTimeoutMillis = 5000
			cfg.Limits.ShutdownTimeoutMillis = 300
		})
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, respFrame("PING"))
		requireWire(t, conn, "+PONG\r\n")
		frame := respFrame("EVAL", publicRedisListLengthScript, "1", key)
		sendWire(t, conn, frame[:len(frame)-1])
		start := time.Now()
		if err := f.stop(); err != nil {
			t.Fatal("shutdown blocked on an incomplete script frame")
		}
		requireClosed(t, conn)
		if time.Since(start) > time.Second || activeConnections(f.server.respLn) != 0 {
			t.Fatal("shutdown failed to reap the script reader within its existing budget")
		}
	})
}

func TestRedisFixtureConnectionQuotaIsUnchanged(t *testing.T) {
	f, key := startRedisFixture(t, 0, func(cfg *config) { cfg.Limits.RESPConnections = 1 })
	first := dialTest(t, f.config.RESPAddress)
	sendWire(t, first, respFrame("LLEN", key))
	requireWire(t, first, ":0\r\n")
	excess := dialTest(t, f.config.RESPAddress)
	requireClosed(t, excess)
	eventually(t, func() bool { return f.state(t).RejectedRESPConnections == 1 })
	_ = first.Close()
	eventually(t, func() bool { return activeConnections(f.server.respLn) == 0 })
	replacement := dialTest(t, f.config.RESPAddress)
	sendWire(t, replacement, respFrame("LLEN", key))
	requireWire(t, replacement, ":0\r\n")
}

func concurrentMetricQueries(f *testObserver, key string) error {
	conn, err := net.DialTimeout("tcp", f.config.RESPAddress, testDeadline)
	if err != nil {
		return errors.New("concurrent fixture dial failed")
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		return errors.New("concurrent fixture deadline failed")
	}
	for range 8 {
		if _, err := io.WriteString(conn, respFrame("EVAL", publicRedisListLengthScript, "1", key)); err != nil {
			return errors.New("concurrent fixture write failed")
		}
		var reply [4]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != ":0\r\n" {
			return errors.New("concurrent fixture integer response failed")
		}
	}
	return nil
}

func TestRedisFixtureConcurrentQueriesSnapshotsAndResets(t *testing.T) {
	f, key := startRedisFixture(t, 0, func(cfg *config) { cfg.Limits.RESPObservations = 4 })
	stop := make(chan struct{})
	reader := make(chan error, 1)
	go func() { reader <- concurrentSnapshots(f, stop) }()
	errs := make(chan error, 5)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() { errs <- concurrentMetricQueries(f, key) })
	}
	group.Go(func() { errs <- concurrentResets(f, 8) })
	group.Wait()
	close(errs)
	close(stop)
	if err := <-reader; err != nil {
		t.Fatal(err)
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	state := f.state(t)
	if state.Generation != 9 || len(state.RESP) > 4 {
		t.Fatal("concurrent metric matching violated generation or evidence bounds")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 9), nil),
		http.StatusOK)
	conn := dialTest(t, f.config.RESPAddress)
	sendWire(t, conn, respFrame("EVAL", publicRedisListLengthScript, "1", key))
	requireWire(t, conn, ":0\r\n")
	state = f.state(t)
	if state.Generation != 10 || len(state.RESP) != 1 || !state.RESP[0].MetricQueryMatched {
		t.Fatal("final isolated normal metric query did not survive concurrent reset traffic")
	}
}
