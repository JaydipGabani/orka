/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package store

import (
	"testing"
	"time"
)

func TestGatewayEventsHaveSameEnvelope(t *testing.T) {
	const changedSuffix = "-other"
	occurredAt := time.Date(2026, time.July, 25, 12, 34, 56, 789012345, time.FixedZone("fixture", -7*60*60))
	base := GatewayEvent{
		ID: "event-one", Namespace: "default", NamespaceUID: "namespace-uid",
		GatewayUID: "gateway-uid", GatewayName: "chat", ExternalEventID: "external-event",
		ProtocolVersion: "orka.gateway.v1", EventType: "text", AccountID: "account",
		ContextID: "context", ThreadID: "thread", SenderID: "sender", SenderDisplayName: "Sender",
		Text: "hello", ReplyTarget: "reply", Metadata: map[string]string{"alpha": "one", "beta": "two"},
		OccurredAt: &occurredAt, State: GatewayEventQueued, StateMessage: "mutable state",
	}

	equivalentOccurredAt := occurredAt.UTC()
	equivalent := base
	equivalent.ID = "event-two"
	equivalent.State = GatewayEventCompleted
	equivalent.StateMessage = "different mutable state"
	equivalent.Metadata = map[string]string{"beta": "two", "alpha": "one"}
	equivalent.OccurredAt = &equivalentOccurredAt
	if !GatewayEventsHaveSameEnvelope(&base, &equivalent) {
		t.Fatal("GatewayEventsHaveSameEnvelope() = false for equivalent envelope with different event ID and mutable state")
	}
	if got, want := GatewayEventEnvelopeDigest(&equivalent), GatewayEventEnvelopeDigest(&base); got != want {
		t.Fatalf("equivalent envelope digest = %q, want %q", got, want)
	}

	emptyMetadata := base
	emptyMetadata.Metadata = nil
	emptyMapMetadata := emptyMetadata
	emptyMapMetadata.Metadata = map[string]string{}
	if !GatewayEventsHaveSameEnvelope(&emptyMetadata, &emptyMapMetadata) {
		t.Fatal("GatewayEventsHaveSameEnvelope() distinguished nil and empty metadata")
	}

	if GatewayEventsHaveSameEnvelope(nil, nil) || GatewayEventsHaveSameEnvelope(&base, nil) {
		t.Fatal("GatewayEventsHaveSameEnvelope() accepted nil event")
	}

	differentOccurredAt := occurredAt.Add(time.Nanosecond)
	changes := []struct {
		name   string
		mutate func(*GatewayEvent)
	}{
		{name: "namespace", mutate: func(event *GatewayEvent) { event.Namespace += changedSuffix }},
		{name: "namespace UID", mutate: func(event *GatewayEvent) { event.NamespaceUID += changedSuffix }},
		{name: "gateway UID", mutate: func(event *GatewayEvent) { event.GatewayUID += changedSuffix }},
		{name: "gateway name", mutate: func(event *GatewayEvent) { event.GatewayName += changedSuffix }},
		{name: "external event ID", mutate: func(event *GatewayEvent) { event.ExternalEventID += changedSuffix }},
		{name: "protocol version", mutate: func(event *GatewayEvent) { event.ProtocolVersion += changedSuffix }},
		{name: "event type", mutate: func(event *GatewayEvent) { event.EventType += changedSuffix }},
		{name: "account ID", mutate: func(event *GatewayEvent) { event.AccountID += changedSuffix }},
		{name: "context ID", mutate: func(event *GatewayEvent) { event.ContextID += changedSuffix }},
		{name: "thread ID", mutate: func(event *GatewayEvent) { event.ThreadID += changedSuffix }},
		{name: "sender ID", mutate: func(event *GatewayEvent) { event.SenderID += changedSuffix }},
		{name: "sender display name", mutate: func(event *GatewayEvent) { event.SenderDisplayName += changedSuffix }},
		{name: "text", mutate: func(event *GatewayEvent) { event.Text += changedSuffix }},
		{name: "reply target", mutate: func(event *GatewayEvent) { event.ReplyTarget += changedSuffix }},
		{name: "occurred at", mutate: func(event *GatewayEvent) { event.OccurredAt = &differentOccurredAt }},
		{name: "metadata", mutate: func(event *GatewayEvent) { event.Metadata = map[string]string{"alpha": "changed"} }},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			candidate := base
			change.mutate(&candidate)
			if GatewayEventsHaveSameEnvelope(&base, &candidate) {
				t.Fatal("GatewayEventsHaveSameEnvelope() = true after envelope field changed")
			}
			if got, want := GatewayEventEnvelopeDigest(&candidate), GatewayEventEnvelopeDigest(&base); got == want {
				t.Fatalf("changed envelope digest = %q, want different from %q", got, want)
			}
		})
	}
}

func TestGatewayEventEnvelopeDigestStable(t *testing.T) {
	occurredAt := time.Date(2026, time.July, 25, 12, 34, 56, 789012345, time.FixedZone("fixture", -7*60*60))
	event := GatewayEvent{
		Namespace: "default", NamespaceUID: "namespace-uid", GatewayUID: "gateway-uid", GatewayName: "chat",
		ExternalEventID: "external-event", ProtocolVersion: "orka.gateway.v1", EventType: "text",
		AccountID: "account", ContextID: "context", ThreadID: "thread", SenderID: "sender",
		SenderDisplayName: "Sender", Text: "hello", ReplyTarget: "reply",
		OccurredAt: &occurredAt, Metadata: map[string]string{"alpha": "one", "beta": "two"},
	}
	const want = "0989f61874e65198bb7d4248de2977f55cf28d154dd6468fd89aa91079093394"
	if got := GatewayEventEnvelopeDigest(&event); got != want {
		t.Fatalf("GatewayEventEnvelopeDigest() = %q, want %q", got, want)
	}
}
