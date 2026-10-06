package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	respOK          = "+OK\r\n"
	respPong        = "+PONG\r\n"
	respUnsupported = "-ERR unsupported\r\n"
	respMalformed   = "-ERR malformed frame\r\n"
	respHello       = "%2\r\n+server\r\n+synthetic-observer\r\n+proto\r\n:3\r\n"
	respNoScript    = "-NOSCRIPT No matching script. Please use EVAL.\r\n"

	respAuthCommand    = "AUTH"
	respHelloCommand   = "HELLO"
	respEvalCommand    = "EVAL"
	respEvalSHACommand = "EVALSHA"
	respLLenCommand    = "LLEN"

	// KEDA v2.17.3, e615440f24f6abec8b7c69bd88854cb4324e9eaa:
	// pkg/scalers/redis_scaler.go:123-136. SHA1 is only the Redis protocol selector.
	kedaRedisScriptSHA256 = "9a20e2b1ef3a3418d5532cdf4a8ef935b423a0c44cb93310965da8fa90683a68"
	kedaRedisScriptSHA1   = "249269d94f90c85be8630a56564ef51c1b3b851b"
)

type respReader struct {
	reader *bufio.Reader
	budget *io.LimitedReader
}

func newRESPReader(reader io.Reader, limit int) *respReader {
	budget := &io.LimitedReader{R: reader, N: int64(limit)}
	return &respReader{reader: bufio.NewReaderSize(budget, 512), budget: budget}
}

func (r *respReader) length(prefix byte, maximum int) (int, error) {
	line, err := r.reader.ReadSlice('\n')
	if err != nil {
		return 0, err
	}
	if len(line) < 4 || len(line) > 16 || line[0] != prefix || line[len(line)-2] != '\r' {
		return 0, errors.New("invalid RESP length")
	}
	digits := line[1 : len(line)-2]
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid RESP length")
		}
	}
	size, err := strconv.Atoi(string(digits))
	if err != nil || size > maximum {
		return 0, errors.New("RESP length exceeds bound")
	}
	return size, nil
}

func (r *respReader) frame() ([][]byte, error) {
	count, err := r.length('*', 16)
	if err != nil || count == 0 {
		return nil, errors.New("invalid RESP array")
	}
	args := make([][]byte, 0, count)
	for range count {
		arg, err := r.bulk()
		if err != nil {
			clearArgs(args)
			return nil, err
		}
		args = append(args, arg)
	}
	return args, nil
}

func (r *respReader) bulk() ([]byte, error) {
	size, err := r.length('$', maxProtocolBytes)
	if err != nil {
		return nil, err
	}
	if int64(size)+2 > r.budget.N+int64(r.reader.Buffered()) {
		return nil, errors.New("RESP byte budget exhausted")
	}
	data := make([]byte, size+2)
	if _, err := io.ReadFull(r.reader, data); err != nil || !bytes.Equal(data[size:], []byte("\r\n")) {
		clear(data)
		return nil, errors.New("invalid RESP bulk string")
	}
	return data[:size], nil
}

func (o *observer) handleRESP(conn net.Conn, generation uint64) {
	defer func() { _ = conn.Close() }()
	timeout := time.Duration(o.config.Limits.RESPReadTimeoutMillis) * time.Millisecond
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	reader := newRESPReader(conn, o.config.Limits.RESPBytes)
	for range o.config.Limits.RESPCommands {
		args, err := reader.frame()
		if err != nil {
			_, _ = io.WriteString(conn, respMalformed)
			return
		}
		observation := respObservation{Command: commandName(args[0])}
		observation.SyntheticCredentialObserved = o.syntheticArgs(observation.Command, args)
		response, matched := o.commandResponse(observation.Command, args)
		observation.MetricQueryMatched = matched
		clearArgs(args)
		o.store.recordRESP(generation, observation)
		if _, err := io.WriteString(conn, response); err != nil {
			return
		}
	}
}

func clearArgs(args [][]byte) {
	for _, arg := range args {
		clear(arg)
	}
}

func commandName(value []byte) string {
	for _, name := range [...]string{
		respAuthCommand, "PING", respHelloCommand, "CLIENT", "SELECT",
		respEvalCommand, respEvalSHACommand, respLLenCommand,
	} {
		if bytes.EqualFold(value, []byte(name)) {
			return name
		}
	}
	return "UNKNOWN"
}

func (o *observer) syntheticArgs(command string, args [][]byte) bool {
	var candidates [][]byte
	if command == respAuthCommand {
		candidates = args[1:]
	} else if command == respHelloCommand {
		for index := 2; index+2 < len(args); index++ {
			if bytes.EqualFold(args[index], []byte(respAuthCommand)) {
				candidates = args[index+1 : index+3]
				break
			}
		}
	}
	matched := 0
	for _, value := range candidates {
		digest := sha256.Sum256(value)
		matched |= subtle.ConstantTimeCompare(digest[:], o.canary[:])
	}
	return matched == 1
}

func (o *observer) commandResponse(command string, args [][]byte) (string, bool) {
	switch command {
	case respAuthCommand, "CLIENT", "SELECT":
		return respOK, false
	case "PING":
		return respPong, false
	case respHelloCommand:
		if len(args) >= 2 && bytes.Equal(args[1], []byte("3")) {
			return respHello, false
		}
	}
	return o.redisMetricResponse(command, args)
}

func (o *observer) redisMetricResponse(command string, args [][]byte) (string, bool) {
	if o.config.RedisFixtureQueueLength == nil {
		return respUnsupported, false
	}
	switch command {
	case respLLenCommand:
		if len(args) != 2 || !o.redisFixtureKeyMatches(args[1]) {
			return respUnsupported, false
		}
	case respEvalCommand, respEvalSHACommand:
		if len(args) != 4 || !bytes.Equal(args[2], []byte("1")) || !o.redisFixtureKeyMatches(args[3]) {
			return respUnsupported, false
		}
		if command == respEvalCommand {
			if digestHex(args[1]) != kedaRedisScriptSHA256 {
				return respUnsupported, false
			}
		} else if !bytes.Equal(args[1], []byte(kedaRedisScriptSHA1)) {
			return respNoScript, false
		}
	default:
		return respUnsupported, false
	}
	// The script is never evaluated and the key is never accessed or recorded.
	return ":" + strconv.Itoa(*o.config.RedisFixtureQueueLength) + "\r\n", true
}

func (o *observer) redisFixtureKeyMatches(key []byte) bool {
	return len(key) != 0 && subtle.ConstantTimeCompare(
		[]byte(digestHex(key)), []byte(o.config.RedisFixtureListKeySHA256)) == 1
}
