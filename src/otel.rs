//! Optional OpenTelemetry traces: one span per decision.
//!
//! Export is off unless `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set. With neither set, no exporter,
//! channel, or background task is created and nothing is sent.
//!
//! Spans carry the same bounded, argument-free data as the metrics: sandbox
//! id, tool name, outcome, reason code, decision time, leaf warrant id, and
//! JSON-RPC id. Never arguments, warrant bodies, approvals, or keys.

use crate::proto::openshell::middleware::v1::HttpHeader;
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::{Span, SpanContext, SpanKind, TraceContextExt, Tracer, TracerProvider};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use std::time::SystemTime;

const SERVICE_NAME: &str = "tenuo-openshell-middleware";
/// Longest string attribute. Tool names and JSON-RPC ids are request data, so
/// they are cut rather than trusted to be short.
const MAX_ATTRIBUTE_BYTES: usize = 128;

pub struct DecisionTracer {
    tracer: SdkTracer,
    propagator: TraceContextPropagator,
}

/// Flushes and stops the exporter when dropped.
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

/// One finished decision.
pub struct DecisionSpan<'a> {
    pub name: &'static str,
    pub started: SystemTime,
    pub sandbox_id: &'a str,
    pub tool: Option<&'a str>,
    pub outcome: &'a str,
    pub reason_code: &'a str,
    pub decision_us: u64,
    pub warrant_id: Option<&'a str>,
    pub jsonrpc_id: &'a str,
    /// Result spans only.
    pub status_code: Option<u32>,
    /// Result spans only.
    pub result_bytes: Option<u64>,
}

/// Build a tracer from the standard OTLP environment, or `None` when export
/// is not configured. Must run inside the Tokio runtime.
pub fn from_env() -> Result<Option<(DecisionTracer, OtelGuard)>, String> {
    let lookup = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    from_lookup(lookup)
}

fn from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<(DecisionTracer, OtelGuard)>, String> {
    if lookup("OTEL_SDK_DISABLED").is_some_and(|value| value.eq_ignore_ascii_case("true")) {
        return Ok(None);
    }
    if lookup("OTEL_TRACES_EXPORTER").is_some_and(|value| value == "none") {
        return Ok(None);
    }
    let Some(endpoint) = lookup("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .or_else(|| lookup("OTEL_EXPORTER_OTLP_ENDPOINT"))
    else {
        return Ok(None);
    };
    for name in [
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
    ] {
        if let Some(protocol) = lookup(name) {
            if protocol != "grpc" {
                return Err(format!("{name}={protocol} is not supported; use grpc"));
            }
            break;
        }
    }
    if lookup("OTEL_TRACES_EXPORTER").is_some_and(|value| value != "otlp") {
        return Err("OTEL_TRACES_EXPORTER supports only otlp or none".to_string());
    }
    let mut builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
    if endpoint.starts_with("https://") {
        use opentelemetry_otlp::WithTonicConfig;
        builder =
            builder.with_tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots());
    }
    let exporter = builder
        .build()
        .map_err(|error| format!("OTLP trace exporter: {error}"))?;
    let processor =
        opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor::builder(
            exporter,
            opentelemetry_sdk::runtime::Tokio,
        )
        .build();
    let mut resource = opentelemetry_sdk::Resource::builder();
    if lookup("OTEL_SERVICE_NAME").is_none() {
        resource = resource.with_service_name(SERVICE_NAME);
    }
    let provider = SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(resource.build())
        .build();
    let tracer = provider.tracer(SERVICE_NAME);
    Ok(Some((
        DecisionTracer {
            tracer,
            propagator: TraceContextPropagator::new(),
        },
        OtelGuard { provider },
    )))
}

impl DecisionTracer {
    /// Parent context from a W3C `traceparent` request header, when present
    /// and valid. The header comes from the sandbox, so it only links spans.
    pub fn parent_from_headers(&self, headers: &[HttpHeader]) -> Context {
        self.propagator
            .extract_with_context(&Context::new(), &HeaderExtractor(headers))
    }

    /// Parent context for a span that follows an earlier decision.
    pub fn parent_from_span(&self, parent: Option<&SpanContext>) -> Context {
        match parent {
            Some(parent) => Context::new().with_remote_span_context(parent.clone()),
            None => Context::new(),
        }
    }

    /// Record one finished decision and return its span context.
    pub fn record(&self, parent: &Context, span: DecisionSpan<'_>) -> SpanContext {
        let mut attributes = vec![
            KeyValue::new("openshell.sandbox_id", bounded(span.sandbox_id)),
            KeyValue::new("tenuo.outcome", span.outcome.to_string()),
            KeyValue::new(
                "tenuo.decision_us",
                i64::try_from(span.decision_us).unwrap_or(i64::MAX),
            ),
        ];
        if let Some(tool) = span.tool {
            attributes.push(KeyValue::new("tenuo.tool", bounded(tool)));
        }
        if !span.reason_code.is_empty() {
            attributes.push(KeyValue::new(
                "tenuo.reason_code",
                span.reason_code.to_string(),
            ));
        }
        if let Some(warrant_id) = span.warrant_id {
            attributes.push(KeyValue::new("tenuo.warrant_id", bounded(warrant_id)));
        }
        if !span.jsonrpc_id.is_empty() {
            attributes.push(KeyValue::new(
                "rpc.jsonrpc.request_id",
                bounded(span.jsonrpc_id),
            ));
        }
        if let Some(status_code) = span.status_code {
            attributes.push(KeyValue::new(
                "http.response.status_code",
                i64::from(status_code),
            ));
        }
        if let Some(result_bytes) = span.result_bytes {
            attributes.push(KeyValue::new(
                "tenuo.result_bytes",
                i64::try_from(result_bytes).unwrap_or(i64::MAX),
            ));
        }
        let mut recorded = self
            .tracer
            .span_builder(span.name)
            .with_kind(SpanKind::Internal)
            .with_start_time(span.started)
            .with_attributes(attributes)
            .start_with_context(&self.tracer, parent);
        let context = recorded.span_context().clone();
        recorded.end_with_timestamp(SystemTime::now());
        context
    }
}

struct HeaderExtractor<'a>(&'a [HttpHeader]);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        // Only W3C trace context is read; baggage and other headers are not.
        if key != "traceparent" && key != "tracestate" {
            return None;
        }
        self.0
            .iter()
            .find(|header| header.name == key)
            .map(|header| header.value.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .iter()
            .map(|header| header.name.as_str())
            .filter(|name| *name == "traceparent" || *name == "tracestate")
            .collect()
    }
}

fn bounded(value: &str) -> String {
    if value.len() <= MAX_ATTRIBUTE_BYTES {
        return value.to_string();
    }
    let mut end = MAX_ATTRIBUTE_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceId;
    use opentelemetry_sdk::trace::InMemorySpanExporter;

    fn in_memory() -> (DecisionTracer, SdkTracerProvider, InMemorySpanExporter) {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        (
            DecisionTracer {
                tracer: provider.tracer(SERVICE_NAME),
                propagator: TraceContextPropagator::new(),
            },
            provider,
            exporter,
        )
    }

    fn header(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn span<'a>(tool: Option<&'a str>, jsonrpc_id: &'a str) -> DecisionSpan<'a> {
        DecisionSpan {
            name: "tenuo.authorize",
            started: SystemTime::now(),
            sandbox_id: "sbx",
            tool,
            outcome: "deny",
            reason_code: "tenuo_tool_denied",
            decision_us: 42,
            warrant_id: Some("tnu_wrt_1"),
            jsonrpc_id,
            status_code: None,
            result_bytes: None,
        }
    }

    #[test]
    fn export_is_off_without_an_endpoint() {
        assert!(from_lookup(|_| None).unwrap().is_none());
        let disabled = |name: &str| match name {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://collector:4317".to_string()),
            "OTEL_SDK_DISABLED" => Some("true".to_string()),
            _ => None,
        };
        assert!(from_lookup(disabled).unwrap().is_none());
        let none = |name: &str| match name {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://collector:4317".to_string()),
            "OTEL_TRACES_EXPORTER" => Some("none".to_string()),
            _ => None,
        };
        assert!(from_lookup(none).unwrap().is_none());
    }

    #[test]
    fn only_the_grpc_protocol_is_accepted() {
        let http = |name: &str| match name {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://collector:4318".to_string()),
            "OTEL_EXPORTER_OTLP_PROTOCOL" => Some("http/protobuf".to_string()),
            _ => None,
        };
        assert!(from_lookup(http).is_err());
        let signal_wins = |name: &str| match name {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://collector:4317".to_string()),
            "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL" => Some("http/json".to_string()),
            "OTEL_EXPORTER_OTLP_PROTOCOL" => Some("grpc".to_string()),
            _ => None,
        };
        assert!(from_lookup(signal_wins).is_err());
    }

    #[test]
    fn a_decision_span_has_only_bounded_argument_free_attributes() {
        let (tracer, provider, exporter) = in_memory();
        let long_tool = "t".repeat(400);
        tracer.record(&Context::new(), span(Some(&long_tool), "7"));
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        let keys: Vec<_> = spans[0]
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str().to_string())
            .collect();
        assert_eq!(
            keys,
            [
                "openshell.sandbox_id",
                "tenuo.outcome",
                "tenuo.decision_us",
                "tenuo.tool",
                "tenuo.reason_code",
                "tenuo.warrant_id",
                "rpc.jsonrpc.request_id",
            ]
        );
        let tool = spans[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "tenuo.tool")
            .unwrap();
        assert_eq!(tool.value.as_str().len(), MAX_ATTRIBUTE_BYTES);
    }

    #[test]
    fn a_valid_traceparent_becomes_the_parent_and_junk_is_ignored() {
        let (tracer, provider, exporter) = in_memory();
        let parent = tracer.parent_from_headers(&[
            header("x-other", "1"),
            header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
        ]);
        let first = tracer.record(&parent, span(None, ""));
        assert_eq!(
            first.trace_id(),
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
        );
        let junk = tracer.parent_from_headers(&[header("traceparent", "not-a-trace")]);
        let second = tracer.record(&junk, span(None, ""));
        assert_ne!(second.trace_id(), first.trace_id());
        let child = tracer.record(&tracer.parent_from_span(Some(&first)), span(None, ""));
        assert_eq!(child.trace_id(), first.trace_id());
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans[2].parent_span_id, first.span_id());
    }
}
