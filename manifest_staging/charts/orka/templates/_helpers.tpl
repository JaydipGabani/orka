{{/*
Expand the name of the chart.
*/}}
{{- define "orka.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "orka.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "orka.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "orka.labels" -}}
helm.sh/chart: {{ include "orka.chart" . }}
{{ include "orka.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "orka.selectorLabels" -}}
app.kubernetes.io/name: {{ include "orka.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "orka.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "orka.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the durable controller store PVC name, or return the operator-provided
claim name when one is configured.
*/}}
{{- define "orka.storePVCName" -}}
{{- if .Values.store.persistence.existingClaim -}}
{{- .Values.store.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-store" (include "orka.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Return the immutable memory release stage carried by this chart artifact. A
missing annotation is treated as foundation so repackaging cannot enable
activation by omission. A later activation release must explicitly change the
Chart.yaml annotation together with the controller source gate.
*/}}
{{- define "orka.memoryReleaseStage" -}}
{{- index .Chart.Annotations "memory.orka.ai/release-stage" | default "foundation" -}}
{{- end }}

{{/*
Create release-scoped worker ServiceAccount names. Reserve room for each
suffix so long release names cannot collapse all trust tiers to one name.
*/}}
{{- define "orka.aiWorkerServiceAccountName" -}}
{{- printf "%s-ai-worker" (include "orka.fullname" . | trunc 53 | trimSuffix "-") | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "orka.vendorWorkerServiceAccountName" -}}
{{- printf "%s-vendor-worker" (include "orka.fullname" . | trunc 49 | trimSuffix "-") | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "orka.containerWorkerServiceAccountName" -}}
{{- printf "%s-container-worker" (include "orka.fullname" . | trunc 46 | trimSuffix "-") | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create release-scoped harness-wrapper names while reserving room for suffixes
that must remain valid DNS labels (notably the Service name).
*/}}
{{- define "orka.harnessWrapperName" -}}
{{- printf "%s-agent-harness-wrapper" (include "orka.fullname" . | trunc 41 | trimSuffix "-") | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "orka.harnessWrapperAuthSecretName" -}}
{{- printf "%s-harness-wrapper-auth" (include "orka.fullname" . | trunc 42 | trimSuffix "-") | trunc 63 | trimSuffix "-" }}
{{- end }}


{{/*
Create the namespace for the chart-managed client ServiceAccount.
When namespace isolation is enforced and the controller watches one namespace,
place the default client in that namespace so its token remains usable.
*/}}
{{- define "orka.clientNamespace" -}}
{{- if .Values.client.namespace }}
{{- .Values.client.namespace }}
{{- else if and .Values.controller.enforceNamespaceIsolation .Values.controller.watchNamespace }}
{{- .Values.controller.watchNamespace }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Create release-scoped worker ClusterRole names.
*/}}
{{- define "orka.aiWorkerClusterRoleName" -}}
{{- printf "%s-ai-worker-role" (include "orka.fullname" .) | trunc 253 | trimSuffix "-" }}
{{- end }}

{{- define "orka.vendorWorkerClusterRoleName" -}}
{{- printf "%s-vendor-worker-role" (include "orka.fullname" .) | trunc 253 | trimSuffix "-" }}
{{- end }}

{{- define "orka.containerWorkerClusterRoleName" -}}
{{- printf "%s-container-worker-role" (include "orka.fullname" .) | trunc 253 | trimSuffix "-" }}
{{- end }}

{{/*
Create release-scoped static worker ClusterRoleBinding names.
*/}}
{{- define "orka.aiWorkerClusterRoleBindingName" -}}
{{- printf "%s-ai-worker-rolebinding" (include "orka.fullname" .) | trunc 253 | trimSuffix "-" }}
{{- end }}

{{- define "orka.vendorWorkerClusterRoleBindingName" -}}
{{- printf "%s-vendor-worker-rolebinding" (include "orka.fullname" .) | trunc 253 | trimSuffix "-" }}
{{- end }}

{{- define "orka.containerWorkerClusterRoleBindingName" -}}
{{- printf "%s-container-worker-rolebinding" (include "orka.fullname" .) | trunc 253 | trimSuffix "-" }}
{{- end }}

{{/*
Create a release-scoped OMS KD6 adapter name while reserving room for the
component suffix on long release names.
*/}}
{{- define "orka.omsKd6AdapterName" -}}
{{- printf "%s-oms-kd6-adapter" (include "orka.fullname" . | trunc 47 | trimSuffix "-") | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the PVC name for the OMS KD6 adapter, or return the operator-provided
claim name when one is configured.
*/}}
{{- define "orka.omsKd6AdapterPVCName" -}}
{{- if .Values.omsKd6Adapter.persistence.existingClaim -}}
{{- .Values.omsKd6Adapter.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-oms-kd6-adapter-data" (include "orka.fullname" . | trunc 42 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/*
Fail closed on unsupported or incomplete OMS KD6 adapter configuration.
*/}}
{{- define "orka.omsKd6AdapterValidate" -}}
{{- if .Values.omsKd6Adapter.enabled -}}
{{- if ne (int .Values.omsKd6Adapter.replicas) 1 -}}
{{- fail "omsKd6Adapter supports exactly one active replica" -}}
{{- end -}}
{{- if not .Values.omsKd6Adapter.persistence.enabled -}}
{{- fail "omsKd6Adapter requires durable persistence" -}}
{{- end -}}
{{- $_ := required "omsKd6Adapter.auth.existingSecret is required when the adapter is enabled" .Values.omsKd6Adapter.auth.existingSecret -}}
{{- $_ := required "omsKd6Adapter.auth.tokenKey is required when the adapter is enabled" .Values.omsKd6Adapter.auth.tokenKey -}}
{{- $_ := required "omsKd6Adapter.tls.existingSecret is required when the adapter is enabled" .Values.omsKd6Adapter.tls.existingSecret -}}
{{- $_ := required "omsKd6Adapter.tls.certKey is required when the adapter is enabled" .Values.omsKd6Adapter.tls.certKey -}}
{{- $_ := required "omsKd6Adapter.tls.keyKey is required when the adapter is enabled" .Values.omsKd6Adapter.tls.keyKey -}}
{{- $_ := required "omsKd6Adapter.tls.reloadInterval is required when the adapter is enabled" .Values.omsKd6Adapter.tls.reloadInterval -}}
{{- $_ := required "omsKd6Adapter.kd6.endpoint is required when the adapter is enabled" .Values.omsKd6Adapter.kd6.endpoint -}}
{{- if not (hasPrefix "https://" .Values.omsKd6Adapter.kd6.endpoint) -}}
{{- fail "omsKd6Adapter.kd6.endpoint must be an absolute HTTPS URL" -}}
{{- end -}}
{{- $_ := required "omsKd6Adapter.kd6.auth.existingSecret is required when the adapter is enabled" .Values.omsKd6Adapter.kd6.auth.existingSecret -}}
{{- $_ := required "omsKd6Adapter.kd6.auth.tokenKey is required when the adapter is enabled" .Values.omsKd6Adapter.kd6.auth.tokenKey -}}
{{- if eq (len .Values.omsKd6Adapter.kd6.storeMappings) 0 -}}
{{- fail "omsKd6Adapter.kd6.storeMappings requires at least one store mapping" -}}
{{- end -}}
{{- range $name, $providerStoreID := .Values.omsKd6Adapter.kd6.storeMappings -}}
{{- $_ := required (printf "omsKd6Adapter.kd6.storeMappings[%s] must name a provider store" $name) $providerStoreID -}}
{{- end -}}
{{- end -}}
{{- end }}
