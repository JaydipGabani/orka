package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Public KEDA v2.17.3, e615440f24f6abec8b7c69bd88854cb4324e9eaa,
// pkg/scalers/redis_scaler.go:123-136. Raw-literal whitespace is significant.
const publicRedisListLengthScript = "\n" +
	"\t\tlocal listName = KEYS[1]\n" +
	"\t\tlocal listType = redis.call('type', listName).ok\n" +
	"\t\tlocal cmd = {\n" +
	"\t\t\tzset = 'zcard',\n" +
	"\t\t\tset = 'scard',\n" +
	"\t\t\tlist = 'llen',\n" +
	"\t\t\thash = 'hlen',\n" +
	"\t\t\tnone = 'llen'\n" +
	"\t\t}\n\n" +
	"\t\treturn redis.call(cmd[listType], listName)\n" +
	"\t"

const publicRedisListLengthSHA1 = "249269d94f90c85be8630a56564ef51c1b3b851b"

func startRedisFixture(t *testing.T, length int, change func(*config)) (*testObserver, string) {
	t.Helper()
	key := "synthetic-list-" + syntheticValue()
	f := startTestObserver(t, func(cfg *config) {
		cfg.RedisFixtureQueueLength = &length
		cfg.RedisFixtureListKeySHA256 = wireDigest(key)
		if change != nil {
			change(cfg)
		}
	})
	return f, key
}

func TestRedisFixturePinsPublicScriptBytes(t *testing.T) {
	if len(publicRedisListLengthScript) != 236 ||
		wireDigest(publicRedisListLengthScript) != "9a20e2b1ef3a3418d5532cdf4a8ef935b423a0c44cb93310965da8fa90683a68" {
		t.Fatal("fixture diverged from the verified public KEDA v2.17.3 script")
	}
	sum := sha1.Sum([]byte(publicRedisListLengthScript))
	if hex.EncodeToString(sum[:]) != publicRedisListLengthSHA1 {
		t.Fatal("Redis protocol script selector differs from the verified public script")
	}
}

func TestRedisFixturePublicGoRedisHandshakeAndEVAL(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		name := "default-resp3"
		if fallback {
			name = "resp2-auth-fallback"
		}
		t.Run(name, func(t *testing.T) {
			f, key := startRedisFixture(t, 0, nil)
			conn := dialTest(t, f.config.RESPAddress)
			helloVersion := "3"
			helloReply := "%2\r\n+server\r\n+synthetic-observer\r\n+proto\r\n:3\r\n"
			if fallback {
				helloVersion, helloReply = "2", "-ERR unsupported\r\n"
			}
			frame := respFrame("hello", helloVersion, "auth", "default", f.canary)
			sendWire(t, conn, frame)
			requireWire(t, conn, helloReply)
			commands := 1
			if fallback {
				auth := respFrame("auth", f.canary)
				frame += auth
				sendWire(t, conn, auth)
				requireWire(t, conn, "+OK\r\n")
				commands++
			}
			// go-redis/v9 v9.7.3 pipelines these identity commands before KEDA's PING.
			identity := respFrame("client", "setinfo", "LIB-NAME", "go-redis(,"+runtime.Version()+")") +
				respFrame("client", "setinfo", "LIB-VER", "9.7.3")
			frame += identity
			sendWire(t, conn, identity)
			requireWire(t, conn, "+OK\r\n+OK\r\n")
			ping := respFrame("ping")
			frame += ping
			sendWire(t, conn, ping)
			requireWire(t, conn, "+PONG\r\n")
			query := respFrame("eval", publicRedisListLengthScript, "1", key)
			frame += query
			sendWire(t, conn, query)
			requireWire(t, conn, ":0\r\n")
			commands += 4
			if commands > 16 || len(frame) > 65536 {
				t.Fatal("public normal handshake exceeded existing observer connection budgets")
			}
			state := f.state(t)
			if len(state.RESP) != commands || !state.RESP[0].SyntheticCredentialObserved ||
				state.RESP[commands-2].Command != "PING" || state.RESP[commands-2].MetricQueryMatched ||
				state.RESP[commands-1].Command != "EVAL" || !state.RESP[commands-1].MetricQueryMatched ||
				state.RESP[commands-1].SyntheticCredentialObserved {
				t.Fatal("normal credential/PING/EVAL flow did not produce exact typed evidence")
			}
			for _, event := range state.RESP[:commands-1] {
				if event.MetricQueryMatched {
					t.Fatal("handshake-only traffic was mistaken for a matched metric read")
				}
			}
		})
	}
}

func TestRedisFixtureFixedIntegerResponses(t *testing.T) {
	for _, length := range []int{0, 10} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			f, key := startRedisFixture(t, length, nil)
			conn := dialTest(t, f.config.RESPAddress)
			queries := [][]string{
				{"EVAL", publicRedisListLengthScript, "1", key},
				{"EVALSHA", publicRedisListLengthSHA1, "1", key},
				{"LLEN", key},
			}
			for _, args := range queries {
				sendWire(t, conn, respFrame(args...))
				requireWire(t, conn, ":"+strconv.Itoa(length)+"\r\n")
			}
			state := f.state(t)
			if len(state.RESP) != len(queries) {
				t.Fatal("fixed integer replies did not produce bounded observations")
			}
			for index, event := range state.RESP {
				if event.Command != queries[index][0] || !event.MetricQueryMatched || event.SyntheticCredentialObserved {
					t.Fatal("integer response evidence was not derived from the admitted metric tuple")
				}
			}
		})
	}
}

func TestRedisFixtureUnknownSHAThenKnownEVAL(t *testing.T) {
	f, key := startRedisFixture(t, 0, nil)
	conn := dialTest(t, f.config.RESPAddress)
	sendWire(t, conn, respFrame("EVALSHA", strings.Repeat("0", 40), "1", key))
	requireWire(t, conn, "-NOSCRIPT No matching script. Please use EVAL.\r\n")
	sendWire(t, conn, respFrame("EVAL", publicRedisListLengthScript, "1", key))
	requireWire(t, conn, ":0\r\n")
	state := f.state(t)
	if len(state.RESP) != 2 || state.RESP[0].Command != "EVALSHA" || state.RESP[0].MetricQueryMatched ||
		state.RESP[1].Command != "EVAL" || !state.RESP[1].MetricQueryMatched {
		t.Fatal("NOSCRIPT fallback was not distinguished from the admitted known EVAL")
	}
}

func TestRedisFixtureRejectsOtherTuplesWithoutDisclosure(t *testing.T) {
	f, key := startRedisFixture(t, 0, nil)
	otherKey := "other-list-" + syntheticValue()
	otherScript := "return '" + f.admin + "'"
	cases := []struct {
		name  string
		args  []string
		reply string
	}{
		{"unknown-script", []string{"EVAL", otherScript, "1", key}, "-ERR unsupported\r\n"},
		{"changed-whitespace", []string{"EVAL", publicRedisListLengthScript + "\n", "1", key}, "-ERR unsupported\r\n"},
		{"wrong-key", []string{"EVAL", publicRedisListLengthScript, "1", otherKey}, "-ERR unsupported\r\n"},
		{"empty-key", []string{"EVAL", publicRedisListLengthScript, "1", ""}, "-ERR unsupported\r\n"},
		{"zero-keys", []string{"EVAL", publicRedisListLengthScript, "0", key}, "-ERR unsupported\r\n"},
		{"two-keys", []string{"EVAL", publicRedisListLengthScript, "2", key, otherKey}, "-ERR unsupported\r\n"},
		{"missing-key", []string{"EVAL", publicRedisListLengthScript, "1"}, "-ERR unsupported\r\n"},
		{"argv", []string{"EVAL", publicRedisListLengthScript, "1", key, f.canary}, "-ERR unsupported\r\n"},
		{"sha-wrong-key", []string{"EVALSHA", publicRedisListLengthSHA1, "1", otherKey}, "-ERR unsupported\r\n"},
		{"sha-argv", []string{"EVALSHA", publicRedisListLengthSHA1, "1", key, f.admin}, "-ERR unsupported\r\n"},
		{"llen-wrong-key", []string{"LLEN", otherKey}, "-ERR unsupported\r\n"},
		{"llen-extra-arg", []string{"LLEN", key, f.canary}, "-ERR unsupported\r\n"},
		{"script-load", []string{"SCRIPT", "LOAD", publicRedisListLengthScript}, "-ERR unsupported\r\n"},
		{"arbitrary-write", []string{"SET", key, f.canary}, "-ERR unsupported\r\n"},
		{"arbitrary-command", []string{f.canary, key}, "-ERR unsupported\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialTest(t, f.config.RESPAddress)
			sendWire(t, conn, respFrame(tc.args...))
			requireWire(t, conn, tc.reply)
			_ = conn.Close()
		})
	}
	response := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
	state := decodeState(t, response.body)
	if len(state.RESP) != len(cases) || len(state.HTTP) != 0 {
		t.Fatal("unsupported tuples changed observation shape or crossed into HTTP evidence")
	}
	for _, event := range state.RESP {
		if event.MetricQueryMatched || event.SyntheticCredentialObserved {
			t.Fatal("unknown script, key, command, or ARGV forged a positive observation")
		}
	}
	encodedScript, err := json.Marshal(publicRedisListLengthScript)
	if err != nil {
		t.Fatal("encode the public fixture for disclosure checking")
	}
	assertNoDisclosure(t, response.body, f.admin, f.canary, key, otherKey, otherScript, string(encodedScript))
}

func TestRedisFixtureDisabledPreservesOldResponseShape(t *testing.T) {
	f := startTestObserver(t, nil)
	key := "synthetic-list-" + syntheticValue()
	conn := dialTest(t, f.config.RESPAddress)
	for _, args := range [][]string{
		{"EVAL", publicRedisListLengthScript, "1", key},
		{"EVALSHA", publicRedisListLengthSHA1, "1", key},
		{"LLEN", key},
	} {
		sendWire(t, conn, respFrame(args...))
		requireWire(t, conn, "-ERR unsupported\r\n")
	}
	response := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
	var document struct {
		RESP []json.RawMessage `json:"resp"`
	}
	if err := json.Unmarshal(response.body, &document); err != nil || len(document.RESP) != 3 {
		t.Fatal("disabled fixture did not retain the bounded RESP evidence array")
	}
	for _, observation := range document.RESP {
		requireJSONKeys(t, observation, "command", "syntheticCredentialObserved")
	}
}

func TestRedisFixtureMatchedFlagIsTypedAndDerived(t *testing.T) {
	f, key := startRedisFixture(t, 0, nil)
	conn := dialTest(t, f.config.RESPAddress)
	sendWire(t, conn, respFrame("AUTH", f.canary))
	requireWire(t, conn, "+OK\r\n")
	sendWire(t, conn, respFrame("EVAL", publicRedisListLengthScript, "1", key))
	requireWire(t, conn, ":0\r\n")
	response := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
	var document struct {
		RESP []json.RawMessage `json:"resp"`
	}
	if err := json.Unmarshal(response.body, &document); err != nil || len(document.RESP) != 2 {
		t.Fatal("typed metric evidence array was missing")
	}
	requireJSONKeys(t, document.RESP[0], "command", "syntheticCredentialObserved")
	requireJSONKeys(t, document.RESP[1], "command", "syntheticCredentialObserved", "metricQueryMatched")
	state := decodeState(t, response.body)
	if !state.RESP[0].SyntheticCredentialObserved || state.RESP[0].MetricQueryMatched ||
		state.RESP[1].SyntheticCredentialObserved || !state.RESP[1].MetricQueryMatched {
		t.Fatal("credential and metric success flags were conflated")
	}
	assertNoDisclosure(t, response.body, key, f.canary, f.admin, f.config.RedisFixtureListKeySHA256)
}

func TestRedisFixtureReceiversKeepIndependentCanariesAndRuns(t *testing.T) {
	receivers := make([]*testObserver, 0, 3)
	keys := make([]string, 0, 3)
	for _, runID := range []string{"same-namespace", "delegated-cta", "unauthorized-target"} {
		f, key := startRedisFixture(t, 0, func(cfg *config) { cfg.RunID = runID })
		receivers = append(receivers, f)
		keys = append(keys, key)
	}
	for index, f := range receivers {
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, respFrame("AUTH", receivers[(index+1)%len(receivers)].canary))
		requireWire(t, conn, "+OK\r\n")
		sendWire(t, conn, respFrame("AUTH", f.canary))
		requireWire(t, conn, "+OK\r\n")
		sendWire(t, conn, respFrame("EVAL", publicRedisListLengthScript, "1", keys[index]))
		requireWire(t, conn, ":0\r\n")
		state := f.state(t)
		if state.RunID != f.config.RunID || len(state.RESP) != 3 ||
			state.RESP[0].SyntheticCredentialObserved || !state.RESP[1].SyntheticCredentialObserved ||
			!state.RESP[2].MetricQueryMatched {
			t.Fatal("controller-selected receiver identity or known-canary classification was conflated")
		}
	}
}
