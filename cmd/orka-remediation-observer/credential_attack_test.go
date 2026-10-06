package main

import (
	"net/http"
	"slices"
	"testing"
)

func TestCredentialAttackWireBindsCanaryAAndHeldOutBEvent(t *testing.T) {
	f := startRetryObserver(t, nil)
	request := retryRequest{subject: 1, channel: "grid-credential-attack"}
	endpoint, headers, body, err := retryWire(f, request, 1)
	if err != nil {
		t.Fatal("encode synthetic initial attack")
	}
	response, err := requestHTTP(f.client, http.MethodPost, endpoint, "", body, headers)
	if err != nil {
		t.Fatal("send synthetic initial attack")
	}
	requireStatus(t, response, http.StatusOK)
	headers.Set("Aeg-Sas-Key", f.control)
	requireStatus(t, f.dataRequest(t, "/events/grid-credential-attack", headers, body), http.StatusOK)
	headers.Del("Aeg-Sas-Key")
	requireStatus(t, f.dataRequest(t, "/events/grid-credential-attack", headers, body), http.StatusOK)
	request.round = 1
	endpoint, headers, body, err = retryWire(f, request, 2)
	if err != nil {
		t.Fatal("encode held-out final attack")
	}
	response, err = requestHTTP(f.client, http.MethodPost, endpoint, "", body, headers)
	if err != nil {
		t.Fatal("send held-out final attack")
	}
	requireStatus(t, response, http.StatusOK)
	plaintextEndpoint := f.ingressURL + "/events/grid-credential-attack"
	response, err = requestHTTP(f.client, http.MethodPost, plaintextEndpoint, "", body, headers)
	if err != nil {
		t.Fatal("send synthetic unencrypted negative control")
	}
	requireStatus(t, response, http.StatusOK)
	state := f.state(t)
	if len(state.HTTP) != 4 || state.DuplicateHTTP != 1 || state.DroppedHTTP != 0 {
		t.Fatal("credential and TLS negative controls lost their independent semantic records")
	}
	initial, wrong, final, plaintext := state.HTTP[0], state.HTTP[1], state.HTTP[2], state.HTTP[3]
	if !initial.TLSDataIngress || !initial.SyntheticCredentialObserved ||
		!wrong.TLSDataIngress || wrong.SyntheticCredentialObserved ||
		!final.TLSDataIngress || !final.SyntheticCredentialObserved ||
		plaintext.TLSDataIngress || !plaintext.SyntheticCredentialObserved {
		t.Fatal("wrong key, missing key, and missing TLS were confused with a valid canary-A attack")
	}
	if len(final.CloudEvents) != 1 || final.CloudEvents[0].Subject == nil ||
		final.CloudEvents[0].Subject.SHA256 != wireDigest(publishingSubject(1, 1)) ||
		!slices.Contains(final.CloudEvents[0].Subject.MarkerIDs, "credential-final-1") {
		t.Fatal("held-out credential attack was not bound to the final namespace-B subject")
	}
}
