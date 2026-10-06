package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func configLookup(value string, present bool) func(string) (string, bool) {
	return func(key string) (string, bool) {
		if key != configEnvironment {
			return "", false
		}
		return value, present
	}
}

func TestCLIConfigSources(t *testing.T) {
	cfg := testConfig(syntheticValue())
	data := configJSON(t, cfg)
	path := filepath.Join(testFiles(t), "observer.json")
	writeTestFile(t, path, data, 0600)
	cases := []struct {
		name    string
		args    []string
		env     string
		present bool
		valid   bool
	}{
		{"file", []string{"-config", path}, "", false, true},
		{"environment", nil, string(data), true, true},
		{"missing", nil, "", false, false},
		{"both", []string{"-config", path}, string(data), true, false},
		{"empty-environment", nil, "", true, false},
		{"repeated-flag", []string{"-config", path, "-config", path}, "", false, false},
		{"empty-flag", []string{"-config="}, "", false, false},
		{"unknown-flag", []string{"--unknown"}, string(data), true, false},
		{"positional", []string{"unexpected"}, string(data), true, false},
		{"missing-file", []string{"-config", path + ".missing"}, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadCLIConfig(tc.args, configLookup(tc.env, tc.present))
			if (err == nil) != tc.valid {
				t.Fatal("CLI did not require exactly one unambiguous configuration source")
			}
			if tc.valid && !reflect.DeepEqual(got, cfg) {
				t.Fatal("CLI configuration did not preserve the trusted input")
			}
		})
	}
	if _, err := loadCLIConfig([]string{"-help"}, configLookup("", false)); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("CLI help was not recognized")
	}
}

func TestRunFailureLogsAreRedacted(t *testing.T) {
	secret := syntheticValue()
	cfg := testConfig(secret)
	cfg.AdminTokenFile = filepath.Join(testFiles(t), "not-present.key")
	cases := []struct {
		name   string
		args   []string
		value  string
		status int
		output string
	}{
		{"flags", []string{"--" + secret}, "", 1, "remediation-observer: configuration rejected\n"},
		{"json", nil, secret, 1, "remediation-observer: configuration rejected\n"},
		{"startup", nil, string(configJSON(t, cfg)), 1, "remediation-observer: startup failed\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			status := run(context.Background(), tc.args, configLookup(tc.value, true), &output)
			assertNoDisclosure(t, output.Bytes(), secret, cfg.Markers[0].Value, cfg.Markers[1].Value)
			if status != tc.status || output.String() != tc.output {
				t.Fatal("failed command did not produce only its fixed redacted lifecycle message")
			}
		})
	}
	var help bytes.Buffer
	if run(context.Background(), []string{"-help"}, configLookup("", false), &help) != 0 ||
		!bytes.Contains(help.Bytes(), []byte("Usage: orka-remediation-observer -config FILE")) {
		t.Fatal("command help failed")
	}
}

func TestStartupFailureReleasesListenerAndRecovers(t *testing.T) {
	cfg := testConfig(syntheticValue())
	admin := syntheticValue()
	cfg.AdminTokenFile = filepath.Join(testFiles(t), "admin.key")
	writeTestFile(t, cfg.AdminTokenFile, []byte(admin), 0600)
	httpReservation, respBlocker := testListener(t), testListener(t)
	cfg.HTTPAddress, cfg.RESPAddress = httpReservation.Addr().String(), respBlocker.Addr().String()
	if err := httpReservation.Close(); err != nil {
		t.Fatal("release reserved HTTP address")
	}
	if server, err := startServer(cfg); err == nil {
		_ = server.shutdown()
		t.Fatal("startup ignored an occupied RESP listener")
	}
	probe, err := net.Listen("tcp", cfg.HTTPAddress)
	if err != nil {
		t.Fatal("failed startup leaked its HTTP listener")
	}
	_ = probe.Close()
	_ = respBlocker.Close()
	server, err := startServer(cfg)
	if err != nil {
		t.Fatalf("startup did not recover after releasing the occupied port: %v", err)
	}
	t.Cleanup(func() {
		if err := server.shutdown(); err != nil {
			t.Errorf("cleanup recovered server: %v", err)
		}
	})
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: testDeadline}
	t.Cleanup(client.CloseIdleConnections)
	response, err := requestHTTP(client, http.MethodGet, "http://"+cfg.HTTPAddress+"/state", admin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, response, http.StatusOK)
	if decodeState(t, response.body).Generation != 1 {
		t.Fatal("recovered startup did not initialize evidence")
	}
	conn := dialTest(t, cfg.RESPAddress)
	sendWire(t, conn, respFrame("PING"))
	requireWire(t, conn, "+PONG\r\n")
}

func TestObserverProcessHelper(t *testing.T) {
	if os.Getenv("ORKA_OBSERVER_TEST_PROCESS") != "1" {
		t.Skip("subprocess entry point")
	}
	os.Args = []string{"orka-remediation-observer"}
	if path := os.Getenv("ORKA_OBSERVER_TEST_CONFIG_FILE"); path != "" {
		os.Args = append(os.Args, "-config", path)
	}
	os.Exit(mainExit())
}

func TestObserverCommandWireAndSIGTERM(t *testing.T) {
	for _, splitIngress := range []bool{false, true} {
		name := "legacy"
		if splitIngress {
			name = "tls-admin-and-plaintext-ingress"
		}
		t.Run(name, func(t *testing.T) { runObserverCommandWire(t, splitIngress) })
	}
}

func runObserverCommandWire(t *testing.T, splitIngress bool) {
	t.Helper()
	admin, canary, control := syntheticValue(), syntheticValue(), syntheticValue()
	cfg := testConfig(canary)
	cfg.Limits.HTTPReadTimeoutMillis = 5000
	cfg.Limits.RESPReadTimeoutMillis = 5000
	cfg.Limits.ShutdownTimeoutMillis = 300
	cfg.AdminTokenFile = filepath.Join(testFiles(t), "admin.key")
	writeTestFile(t, cfg.AdminTokenFile, []byte(admin), 0600)
	httpReservation, respReservation := testListener(t), testListener(t)
	cfg.HTTPAddress, cfg.RESPAddress = httpReservation.Addr().String(), respReservation.Addr().String()
	var clientTLS *tls.Config
	var ingressReservation net.Listener
	if splitIngress {
		cfg.TLS, clientTLS = syntheticTLS(t)
		ingressReservation = testListener(t)
		cfg.IngressHTTPAddress = ingressReservation.Addr().String()
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate command test executable")
	}
	command := exec.Command(executable, "-test.run=^TestObserverProcessHelper$")
	command.Env = []string{
		"ORKA_OBSERVER_TEST_PROCESS=1",
		"GORACE=atexit_sleep_ms=0", "GOCOVERDIR=" + filepath.Dir(cfg.AdminTokenFile),
	}
	if splitIngress {
		path := filepath.Join(filepath.Dir(cfg.AdminTokenFile), "observer.json")
		writeTestFile(t, path, configJSON(t, cfg), 0400)
		command.Env = append(command.Env, "ORKA_OBSERVER_TEST_CONFIG_FILE="+path)
	} else {
		command.Env = append(command.Env, configEnvironment+"="+string(configJSON(t, cfg)))
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	_ = httpReservation.Close()
	_ = respReservation.Close()
	if ingressReservation != nil {
		_ = ingressReservation.Close()
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start observer command process: %v", err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() {
		exitErr = command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(testDeadline):
				t.Error("command process did not exit during cleanup")
			}
		}
	})
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true},
		Timeout:   250 * time.Millisecond,
	}
	t.Cleanup(client.CloseIdleConnections)
	url := "http://" + cfg.HTTPAddress
	if splitIngress {
		url = "https://" + cfg.HTTPAddress
	}
	eventually(t, func() bool {
		response, err := requestHTTP(client, http.MethodGet, url+"/healthz", "", nil, nil)
		return err == nil && response.status == http.StatusOK
	})
	resp := dialTest(t, cfg.RESPAddress)
	sendWire(t, resp, respFrame("AUTH", canary)+respFrame("AUTH", control))
	requireWire(t, resp, "+OK\r\n+OK\r\n")
	body := cfg.Markers[0].Value + canary
	ingressURL := url
	if splitIngress {
		ingressURL = "http://" + cfg.IngressHTTPAddress
	}
	response, err := requestHTTP(client, http.MethodPost, ingressURL+"/events/alpha", "", []byte(body),
		http.Header{"Aeg-Sas-Key": {canary}})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, response, http.StatusOK)
	response, err = requestHTTP(client, http.MethodGet, url+"/state", admin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, response, http.StatusOK)
	assertNoDisclosure(t, response.body, admin, canary, control, body, cfg.Markers[0].Value)
	state := decodeState(t, response.body)
	if len(state.HTTP) != 1 || len(state.RESP) != 2 || !state.HTTP[0].SyntheticCredentialObserved ||
		!state.RESP[0].SyntheticCredentialObserved || state.RESP[1].SyntheticCredentialObserved {
		t.Fatal("command process lost digest-positive evidence or falsely marked its own control")
	}
	stallAddress := cfg.HTTPAddress
	var stalledHandshake net.Conn
	if splitIngress {
		for _, path := range []string{"/state", "/reset"} {
			response, err := requestHTTP(client, http.MethodPost, ingressURL+path, admin,
				resetBody(cfg.RunID, 1), nil)
			if err != nil {
				t.Fatal(err)
			}
			requireStatus(t, response, http.StatusNotFound)
			assertNoDisclosure(t, response.body, admin, canary, control)
		}
		stallAddress = cfg.IngressHTTPAddress
		stalledHandshake = dialTest(t, cfg.HTTPAddress)
		sendWire(t, stalledHandshake, "\x16")
	}
	stalledHTTP, _ := beginHTTPBody(t, stallAddress, 100)
	sendWire(t, resp, "*1\r\n$4\r\nPI")
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("signal observer process")
	}
	select {
	case <-done:
	case <-time.After(testDeadline):
		t.Fatal("SIGTERM did not reap the command with stalled readers")
	}
	if exitErr != nil {
		t.Fatal("observer command exited unsuccessfully after SIGTERM")
	}
	requireClosed(t, stalledHTTP)
	requireClosed(t, resp)
	if stalledHandshake != nil {
		requireClosed(t, stalledHandshake)
	}
	assertNoDisclosure(t, output.Bytes(), admin, canary, control, body, cfg.Markers[0].Value)
	if output.String() != "remediation-observer: started\nremediation-observer: stopped\n" {
		t.Fatal("command logs were not limited to fixed lifecycle messages")
	}
}
