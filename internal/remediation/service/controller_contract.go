package service

const eventPublishingVerificationContract = "For this approved event-source scenario, namespaced CloudEventSource must not " +
	"receive other namespaces' events or send cluster-wide Event Grid shared-key credentials to a namespace writer's endpoint. " +
	"An undelegated ClusterTriggerAuthentication reference is an attack, not authorization. Preserve namespace-local " +
	"TriggerAuthentication, legitimate cluster-scoped HTTP events, and unchanged ScaledObject/ScaledJob cluster-auth semantics. " +
	"The adapter supplies controlled local HTTP/HTTPS receivers and synthetic identities, not real Azure authorization evidence. " +
	"Exact downstream image/recipe binding and positive original/control observations are still required before any fix is qualified."
