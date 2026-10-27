{{/*
Expand the name of the chart.
*/}}
{{- define "aws-watchdog.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "aws-watchdog.fullname" -}}
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
Common labels
*/}}
{{- define "aws-watchdog.labels" -}}
helm.sh/chart: {{ include "aws-watchdog.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "aws-watchdog.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "aws-watchdog.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aws-watchdog.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
