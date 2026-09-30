{{- define "tenuo-openshell.name" -}}
tenuo-openshell
{{- end }}

{{- define "tenuo-openshell.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "tenuo-openshell.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "tenuo-openshell.labels" -}}
app.kubernetes.io/name: {{ include "tenuo-openshell.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
