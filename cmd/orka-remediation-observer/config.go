package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"strings"
)

const (
	schemaVersion            = "v1"
	configEnvironment        = "ORKA_REMEDIATION_OBSERVER_CONFIG"
	maxConfigBytes           = 64 * 1024
	maxProtocolBytes         = 64 * 1024
	maxObservations          = 256
	maxConnections           = 16
	maxPublishingConnections = 256
	adminConnections         = 2
	maxCommands              = 16
	maxMarkers               = 32
	maxChannels              = 32
	maxCloudEvents           = 16
	maxAdminTokenBytes       = 4096
	adminHeader              = "X-Orka-Observer-Token"
)

type markerConfig struct {
	ID     string `json:"id"`
	Value  string `json:"value,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type tlsFiles struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type channelCanaryConfig struct {
	Channel string `json:"channel"`
	SHA256  string `json:"sha256"`
}

type limits struct {
	HTTPBodyBytes         int `json:"httpBodyBytes"`
	HTTPObservations      int `json:"httpObservations"`
	HTTPConnections       int `json:"httpConnections"`
	HTTPReadTimeoutMillis int `json:"httpReadTimeoutMillis"`
	RESPBytes             int `json:"respBytes"`
	RESPCommands          int `json:"respCommands"`
	RESPConnections       int `json:"respConnections"`
	RESPObservations      int `json:"respObservations"`
	RESPReadTimeoutMillis int `json:"respReadTimeoutMillis"`
	ShutdownTimeoutMillis int `json:"shutdownTimeoutMillis"`
}

type config struct {
	SchemaVersion string `json:"schemaVersion"`
	RunID         string `json:"runID"`
	HTTPAddress   string `json:"httpAddress"`
	// IngressHTTPAddress enables plaintext health, metric, and configured event routes.
	// HTTPAddress must use TLS on a different port; admin routes are never exposed here.
	// Data listeners share evidence and run/generation fences. The publishing
	// profile reserves a separate administration connection pool.
	IngressHTTPAddress string `json:"ingressHTTPAddress"`
	// IngressHTTPSAddress uses the configured TLS identity on a separate data-only
	// listener. Neither ingress listener exposes administrative routes.
	IngressHTTPSAddress   string         `json:"ingressHTTPSAddress,omitempty"`
	RESPAddress           string         `json:"respAddress"`
	AdminTokenFile        string         `json:"adminTokenFile"`
	Markers               []markerConfig `json:"markers"`
	Channels              []string       `json:"channels"`
	SyntheticCanarySHA256 string         `json:"syntheticCanarySHA256"`
	TLS                   tlsFiles       `json:"tls"`
	Limits                limits         `json:"limits"`
	// The compiled publishing profile retains first semantic occurrences and
	// reserves a separate bounded administration connection pool.
	HTTPSetEvidence bool `json:"httpSetEvidence,omitempty"`
	// Overrides the default canary for aeg-sas-key on these exact event channels.
	// Only digests of controller-generated synthetic values are admitted.
	ChannelCanaries []channelCanaryConfig `json:"channelCanaries,omitempty"`
	// These operator-only fixture settings opt into fixed synthetic metric replies.
	// Omission disables them; a RESP listener and one generated list-key digest are required.
	RedisFixtureQueueLength   *int   `json:"redisFixtureQueueLength,omitempty"`
	RedisFixtureListKeySHA256 string `json:"redisFixtureListKeySHA256,omitempty"`
}

func defaultConfig() config {
	return config{
		HTTPAddress: "127.0.0.1:8080",
		Limits: limits{
			HTTPBodyBytes: maxProtocolBytes, HTTPObservations: maxObservations,
			HTTPConnections: maxConnections, HTTPReadTimeoutMillis: 5000,
			RESPBytes: maxProtocolBytes, RESPCommands: maxCommands,
			RESPConnections: maxConnections, RESPObservations: maxObservations,
			RESPReadTimeoutMillis: 5000, ShutdownTimeoutMillis: 2000,
		},
	}
}

func parseConfig(data []byte) (config, error) {
	cfg := defaultConfig()
	if len(data) == 0 || len(data) > maxConfigBytes {
		return config{}, errors.New("configuration size is invalid")
	}
	if err := decodeStrict(data, &cfg); err != nil {
		return config{}, errors.New("configuration JSON is invalid")
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func (c config) validate() error {
	if c.SchemaVersion != schemaVersion || !validID(c.RunID) {
		return errors.New("configuration version or run identity is invalid")
	}
	if !validAddress(c.HTTPAddress) || (c.RESPAddress != "" && !validAddress(c.RESPAddress)) {
		return errors.New("listeners require literal IP addresses and ports above 1024")
	}
	if c.HTTPAddress == c.RESPAddress {
		return errors.New("listeners require distinct addresses")
	}
	if c.AdminTokenFile == "" {
		return errors.New("admin token file is required")
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return errors.New("TLS requires both certificate and key files")
	}
	if err := c.validateIngress(); err != nil {
		return err
	}
	if c.HTTPSetEvidence && c.IngressHTTPSAddress == "" {
		return errors.New("set evidence requires the separate TLS data listener")
	}
	if !c.HTTPSetEvidence && c.Limits.HTTPConnections > maxConnections {
		return errors.New("legacy HTTP connection limit cannot exceed 16")
	}
	if err := c.validateRedisFixture(); err != nil {
		return err
	}
	if _, err := parseDigest(c.SyntheticCanarySHA256); err != nil {
		return errors.New("synthetic canary digest is invalid")
	}
	if err := validateMarkers(c.Markers); err != nil {
		return err
	}
	if len(c.Channels) > maxChannels {
		return errors.New("too many logical channels")
	}
	seen := make(map[string]bool, len(c.Channels))
	for _, channel := range c.Channels {
		if !validID(channel) || seen[channel] {
			return errors.New("logical channels must be unique bounded identifiers")
		}
		seen[channel] = true
	}
	if err := c.validateChannelCanaries(seen); err != nil {
		return err
	}
	return c.Limits.validate()
}

func (c config) validateIngress() error {
	if c.IngressHTTPAddress == "" && c.IngressHTTPSAddress == "" {
		return nil
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return errors.New("data ingress requires TLS on the main HTTP listener")
	}
	ports := make(map[uint16]bool)
	for index, address := range []string{c.HTTPAddress, c.RESPAddress, c.IngressHTTPAddress, c.IngressHTTPSAddress} {
		if address == "" {
			continue
		}
		listener, err := netip.ParseAddrPort(address)
		if err != nil || !validAddress(address) {
			return errors.New("data ingress requires literal IP addresses and ports above 1024")
		}
		if index >= 2 && ports[listener.Port()] {
			return errors.New("data ingress requires distinct listener ports")
		}
		ports[listener.Port()] = true
	}
	return nil
}

func (c config) validateChannelCanaries(channels map[string]bool) error {
	if len(c.ChannelCanaries) > maxChannels {
		return errors.New("too many channel canaries")
	}
	seen := make(map[string]bool, len(c.ChannelCanaries))
	for _, canary := range c.ChannelCanaries {
		sum, err := parseDigest(canary.SHA256)
		if !channels[canary.Channel] || seen[canary.Channel] || err != nil || sum == sha256.Sum256(nil) {
			return errors.New("channel canaries require unique configured channels and nonempty synthetic digests")
		}
		seen[canary.Channel] = true
	}
	return nil
}

func (c config) validateRedisFixture() error {
	if c.RedisFixtureQueueLength == nil {
		if c.RedisFixtureListKeySHA256 != "" {
			return errors.New("synthetic Redis fixture key digest requires an explicit queue length")
		}
		return nil
	}
	if c.RESPAddress == "" {
		return errors.New("synthetic Redis fixture requires a RESP listener")
	}
	if *c.RedisFixtureQueueLength < 0 || *c.RedisFixtureQueueLength > 10 {
		return errors.New("synthetic Redis queue length must be between 0 and 10")
	}
	key, err := parseDigest(c.RedisFixtureListKeySHA256)
	if err != nil || key == sha256.Sum256(nil) {
		return errors.New("synthetic Redis fixture requires a nonempty generated list-key SHA-256 digest")
	}
	return nil
}

func validateMarkers(markers []markerConfig) error {
	if len(markers) == 0 || len(markers) > maxMarkers {
		return errors.New("configuration requires between 1 and 32 markers")
	}
	ids := make(map[string]bool, len(markers))
	values := make(map[string]bool, len(markers))
	for _, marker := range markers {
		if !validID(marker.ID) || ids[marker.ID] || (marker.Value == "") == (marker.SHA256 == "") {
			return errors.New("markers require unique identifiers and exactly one value or SHA-256")
		}
		fingerprint := marker.SHA256
		if marker.SHA256 == "" {
			if len(marker.Value) < 8 || len(marker.Value) > 256 || !printable(marker.Value, true) {
				return errors.New("marker values require 8 to 256 printable bytes")
			}
			fingerprint = digestHex([]byte(marker.Value))
		} else if sum, err := parseDigest(marker.SHA256); err != nil || sum == sha256.Sum256(nil) {
			return errors.New("marker SHA-256 must identify a nonempty synthetic value")
		}
		if values[fingerprint] {
			return errors.New("marker values and digests must be unique")
		}
		ids[marker.ID], values[fingerprint] = true, true
	}
	return nil
}

func (l limits) validate() error {
	bounds := []struct{ value, maximum int }{
		{l.HTTPBodyBytes, maxProtocolBytes}, {l.HTTPObservations, maxObservations},
		{l.HTTPConnections, maxPublishingConnections}, {l.HTTPReadTimeoutMillis, 5000},
		{l.RESPBytes, maxProtocolBytes}, {l.RESPCommands, maxCommands},
		{l.RESPConnections, maxConnections}, {l.RESPObservations, maxObservations},
		{l.RESPReadTimeoutMillis, 5000}, {l.ShutdownTimeoutMillis, 2000},
	}
	for _, bound := range bounds {
		if bound.value <= 0 || bound.value > bound.maximum {
			return errors.New("limits must be positive and cannot exceed the documented hard bounds")
		}
	}
	return nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i, ch := range []byte(value) {
		alnum := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
		if !alnum && (i == 0 || ch != '-' && ch != '_' && ch != '.') {
			return false
		}
	}
	return true
}

func validAddress(address string) bool {
	value, err := netip.ParseAddrPort(address)
	return err == nil && value.Port() > 1024 && value.Addr().Zone() == "" && !value.Addr().IsMulticast()
}

func printable(value string, spaces bool) bool {
	minimum := byte('!')
	if spaces {
		minimum = ' '
	}
	for i := range len(value) {
		if value[i] < minimum || value[i] > '~' {
			return false
		}
	}
	return true
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(result)) || strings.ToLower(value) != value {
		return result, errors.New("invalid digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return result, errors.New("invalid digest")
	}
	copy(result[:], decoded)
	return result, nil
}

func readBoundedFile(path string, limit int, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("configured file cannot be read")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("configured file must be a bounded regular file")
	}
	if private && info.Mode().Perm()&0137 != 0 {
		return nil, errors.New("private file must not be world accessible, executable, or group writable")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		clear(data)
		return nil, errors.New("configured file cannot be read within its bound")
	}
	return data, nil
}

func loadAdminDigest(path string, canary [sha256.Size]byte) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	token, err := readBoundedFile(path, maxAdminTokenBytes, true)
	if err != nil {
		return empty, err
	}
	defer clear(token)
	if len(token) < 32 || !printable(string(token), false) {
		return empty, errors.New("admin token requires 32 to 4096 printable non-space ASCII bytes without a newline")
	}
	digest := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(digest[:], canary[:]) == 1 {
		return empty, errors.New("admin token must be separate from the synthetic canary")
	}
	return digest, nil
}

// Validate tokens before decoding so duplicate keys, case aliases, nulls, and
// unknown fields cannot silently override a trusted controller's configuration.
func decodeStrict(data []byte, output any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := checkJSONValue(decoder, reflect.TypeOf(output).Elem(), 0); err != nil {
		return errors.New("invalid JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("invalid JSON")
	}
	if err := json.Unmarshal(data, output); err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder, expected reflect.Type, depth int) error {
	if depth > 12 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return errors.New("invalid JSON value")
	}
	switch token {
	case json.Delim('{'):
		return checkJSONObject(decoder, expected, depth)
	case json.Delim('['):
		if expected.Kind() != reflect.Slice {
			return errors.New("invalid JSON array")
		}
		for decoder.More() {
			if err := checkJSONValue(decoder, expected.Elem(), depth+1); err != nil {
				return err
			}
		}
		return checkJSONEnd(decoder, ']')
	default:
		if expected.Kind() == reflect.Struct || expected.Kind() == reflect.Slice {
			return errors.New("invalid JSON scalar")
		}
		return nil
	}
}

func checkJSONObject(decoder *json.Decoder, expected reflect.Type, depth int) error {
	if expected.Kind() != reflect.Struct {
		return errors.New("invalid JSON object")
	}
	fields := make(map[string]reflect.Type, expected.NumField())
	for field := range expected.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		fields[name] = field.Type
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		field, known := fields[name]
		if err != nil || !ok || !known || seen[name] {
			return errors.New("invalid JSON object field")
		}
		seen[name] = true
		if err := checkJSONValue(decoder, field, depth+1); err != nil {
			return err
		}
	}
	return checkJSONEnd(decoder, '}')
}

func checkJSONEnd(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil || token != expected {
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
