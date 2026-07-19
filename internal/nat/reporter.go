package nat

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// EndpointReporter abstracts the control plane endpoint reporting API.
type EndpointReporter interface {
	ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointRequest) (*api.EndpointResponse, error)
}

// errEndpointRejected marks a report the control plane refused because it no
// longer holds this node's peer record (endpoint_peer_not_found,
// endpoint_peer_gone). Re-reporting cannot clear either code, so the caller
// tracks how long the condition persists instead of retrying quietly.
var errEndpointRejected = errors.New("control plane rejected the endpoint")

// report sends the discovered endpoint to the control plane and returns the
// server's stale_after deadline. A rejection is wrapped in
// errEndpointRejected so the caller can distinguish it from a transient
// failure; every other error is wrapped as-is.
//
// endpoint_clock_skew is deliberately not retried: reported_at comes from
// the same clock that produced the rejected timestamp, so an immediate
// second attempt carries an equally skewed value and is rejected
// identically — it only doubles the request volume during the NTP incident
// that caused the skew. The heartbeat path reports clock skew with the
// actionable NTP guidance.
func report(ctx context.Context, reporter EndpointReporter, nodeID string, result *DiscoveryResult) (time.Time, error) {
	resp, err := reporter.ReportEndpoint(ctx, nodeID, api.EndpointRequest{
		Endpoint:   result.Endpoint,
		NATType:    result.NATType.Wire(),
		ReportedAt: time.Now().UTC(),
	})
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && (apiErr.Code == "endpoint_peer_not_found" || apiErr.Code == "endpoint_peer_gone") {
			return time.Time{}, fmt.Errorf("nat: report endpoint: %w: %s", errEndpointRejected, apiErr.Code)
		}
		return time.Time{}, fmt.Errorf("nat: report endpoint: %w", err)
	}
	if resp == nil {
		return time.Time{}, nil
	}
	return resp.StaleAfter, nil
}
