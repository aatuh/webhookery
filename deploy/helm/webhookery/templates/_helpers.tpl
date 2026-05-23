{{- define "webhookery.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "webhookery.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "webhookery.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "webhookery.labels" -}}
app.kubernetes.io/name: {{ include "webhookery.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "webhookery.selectorLabels" -}}
app.kubernetes.io/name: {{ include "webhookery.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "webhookery.secretName" -}}
{{- default (printf "%s-secrets" (include "webhookery.fullname" .)) .Values.secret.name -}}
{{- end -}}
