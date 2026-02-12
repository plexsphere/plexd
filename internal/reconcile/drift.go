package reconcile

import (
	"fmt"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// BuildDriftReport constructs an api.DriftReport from a StateDiff.
// Each drift item produces one DriftCorrection entry.
func BuildDriftReport(diff StateDiff) api.DriftReport {
	corrections := make([]api.DriftCorrection, 0)

	for _, p := range diff.PeersToAdd {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "peer_added",
			Detail: fmt.Sprintf("peer %s", p.ID),
		})
	}

	for _, id := range diff.PeersToRemove {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "peer_removed",
			Detail: fmt.Sprintf("peer %s", id),
		})
	}

	for _, p := range diff.PeersToUpdate {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "peer_updated",
			Detail: fmt.Sprintf("peer %s", p.ID),
		})
	}

	for _, pol := range diff.PoliciesToAdd {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "policy_added",
			Detail: fmt.Sprintf("policy %s", pol.ID),
		})
	}

	for _, id := range diff.PoliciesToRemove {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "policy_removed",
			Detail: fmt.Sprintf("policy %s", id),
		})
	}

	if diff.SigningKeysChanged {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "signing_keys_updated",
			Detail: "signing keys rotated",
		})
	}

	if diff.MetadataChanged {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "metadata_updated",
			Detail: "metadata updated",
		})
	}

	if diff.DataChanged {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "data_updated",
			Detail: "data updated",
		})
	}

	if diff.SecretRefsChanged {
		corrections = append(corrections, api.DriftCorrection{
			Type:   "secret_refs_updated",
			Detail: "secret refs updated",
		})
	}

	return api.DriftReport{
		Timestamp:   time.Now(),
		Corrections: corrections,
	}
}
