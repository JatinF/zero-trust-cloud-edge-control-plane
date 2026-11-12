package telemetry

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

type Hub struct {
	register  *prometheus.Registry
	decisions *prometheus.CounterVec
	spans     *tracetest.SpanRecorder
	tracer    trace.Tracer
	provider  *sdktrace.TracerProvider
}

func New(service string) *Hub {
	register := prometheus.NewRegistry()
	decisions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "zt_authz_decisions_total",
		Help: "Local authorization decisions.",
	}, []string{"result"})
	register.MustRegister(decisions)
	spans := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	return &Hub{
		register:  register,
		decisions: decisions,
		spans:     spans,
		tracer:    provider.Tracer(service),
		provider:  provider,
	}
}

func (h *Hub) Handler() http.Handler {
	return promhttp.HandlerFor(h.register, promhttp.HandlerOpts{})
}

func (h *Hub) Decision(result string) {
	h.decisions.WithLabelValues(result).Inc()
}

func (h *Hub) Start(ctx context.Context, name string) (context.Context, func()) {
	ctx, span := h.tracer.Start(ctx, name)
	return ctx, func() { span.End() }
}

func (h *Hub) SpanNames() []string {
	ended := h.spans.Ended()
	names := make([]string, 0, len(ended))
	for _, span := range ended {
		names = append(names, span.Name())
	}
	return names
}
