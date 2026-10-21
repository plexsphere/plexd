package wireguard

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// edgePSKAADPrefix is the versioned domain-separation tag the control plane
// binds into every edge-PSK envelope's additional authenticated data. It must
// stay byte-identical to the control plane's constant in
// internal/mesh/peers/edge_psk.go in plexsphere/plexsphere, or every envelope
// fails to open.
const edgePSKAADPrefix = "plexsphere/mesh/edge-psk/v1|"

// edgePSKSize is the length of an edge PSK, a WireGuard preshared key.
const edgePSKSize = 32

// minEdgePSKPause is the shortest pause a 429 imposes on edge-PSK fetches,
// for an answer whose Retry-After is absent or zero.
const minEdgePSKPause = time.Second

// errEdgePSKOpen is returned for every way an envelope can fail to open. It
// carries no detail: the inputs are key material.
var errEdgePSKOpen = errors.New("wireguard: open edge psk: authentication failed")

// edgePSKAAD rebuilds the additional authenticated data the control plane
// sealed an envelope under: the versioned tag, this node's ID, the peer's ID
// and the PSK epoch, joined by "|". The IDs are lowercased because the control
// plane derives its side from the canonical UUID text; the epoch is
// server-minted and used verbatim.
//
// Binding the two IDs is what keeps a secret envelope (sealed with no AAD) or
// another edge's envelope from opening as this edge's PSK. Binding the epoch is
// what makes the X-Plexsphere-PSK-Epoch header a trustworthy statement of the
// envelope's age, which the epoch floor relies on.
func edgePSKAAD(selfNodeID, peerNodeID, epoch string) []byte {
	return []byte(edgePSKAADPrefix +
		strings.ToLower(strings.TrimSpace(selfNodeID)) + "|" +
		strings.ToLower(strings.TrimSpace(peerNodeID)) + "|" +
		epoch)
}

// openEdgePSK opens env under the node secret key with the edge's additional
// authenticated data and returns the 32-byte PSK. The envelope is
// <12-byte nonce> || <ciphertext + 16-byte GCM tag>. Every cipher or tag
// failure returns errEdgePSKOpen, so no error says anything about the key, the
// NSK or the body.
func openEdgePSK(nsk []byte, env *api.EdgePSKEnvelope, selfNodeID, peerNodeID string) ([edgePSKSize]byte, error) {
	var key [edgePSKSize]byte
	if len(nsk) != 32 {
		return key, errors.New("wireguard: open edge psk: nsk must be 32 bytes")
	}
	if env == nil {
		return key, errEdgePSKOpen
	}
	block, err := aes.NewCipher(nsk)
	if err != nil {
		return key, errEdgePSKOpen
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return key, errEdgePSKOpen
	}
	if len(env.Data) < gcm.NonceSize()+gcm.Overhead() {
		return key, errEdgePSKOpen
	}
	nonce, sealed := env.Data[:gcm.NonceSize()], env.Data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, edgePSKAAD(selfNodeID, peerNodeID, env.Epoch))
	if err != nil {
		return key, errEdgePSKOpen
	}
	defer clear(plaintext)
	if len(plaintext) != edgePSKSize {
		return key, fmt.Errorf("wireguard: open edge psk: plaintext is %d bytes, want %d", len(plaintext), edgePSKSize)
	}
	copy(key[:], plaintext)
	return key, nil
}

// EdgePSKFetcher fetches the sealed PSK for one edge. *api.ControlPlane
// implements it.
type EdgePSKFetcher interface {
	FetchEdgePSK(ctx context.Context, nodeID, peerNodeID string) (*api.EdgePSKEnvelope, error)
}

// EdgePSKInstaller programs an edge PSK on the device peer that carries
// publicKey. *Manager implements it.
type EdgePSKInstaller interface {
	SetPeerPSK(peerNodeID, publicKey string, psk []byte) error
}

// EdgePSKs fetches, opens and installs the pairwise edge PSK of every mesh
// peer, and keeps them in memory for the reconcile handler to program on the
// peers it adds or updates.
//
// It runs the contract's re-fetch rule: a PSK is fetched when a peer first
// appears, when its public key changes, and after this node completes its own
// key rotation (InvalidateAll). A failed fetch is retried on the next pull. An
// envelope whose epoch sorts below the highest one already accepted for the
// edge is refused, because a mesh key rotation does not rotate the NSK and an
// older envelope would reinstall a retired key.
//
// Keys, envelopes and the NSK never reach a log line or an error.
type EdgePSKs struct {
	fetcher   EdgePSKFetcher
	installer EdgePSKInstaller
	nodeID    string
	nsk       []byte
	logger    *slog.Logger
	now       func() time.Time

	mu      sync.Mutex
	entries map[string]*edgePSK // by peer node ID
	// floors holds the highest epoch accepted per peer. It survives a key
	// change, so an envelope from before the peer's rotation is refused too.
	floors map[string]string
	// gen counts InvalidateAll calls, so a fetch in flight while this node
	// rotated stores a stale entry instead of a current one.
	gen       uint64
	retryAt   time.Time
	notServed bool
	stopped   bool
}

// edgePSK is one peer's PSK, fetched for publicKey under epoch.
type edgePSK struct {
	publicKey string
	epoch     string
	key       [edgePSKSize]byte
	// stale marks a PSK this node's own key rotation invalidated. It stays in
	// use until its replacement arrives.
	stale bool
	// installed is set once the installer accepted the key, so a failed
	// device write is retried on the next pull without another fetch.
	installed bool
}

// NewEdgePSKs builds an EdgePSKs for the node nodeID, opening envelopes under
// nsk (copied) and programming PSKs through installer.
func NewEdgePSKs(fetcher EdgePSKFetcher, nodeID string, nsk []byte, installer EdgePSKInstaller, logger *slog.Logger) *EdgePSKs {
	return &EdgePSKs{
		fetcher:   fetcher,
		installer: installer,
		nodeID:    nodeID,
		nsk:       slices.Clone(nsk),
		logger:    logger.With("component", "wireguard"),
		now:       time.Now,
		entries:   make(map[string]*edgePSK),
		floors:    make(map[string]string),
	}
}

// Lookup returns a copy of the PSK held for peerNodeID when it was fetched for
// publicKey, stale or not: a stale PSK stays on the device until its
// replacement arrives. A PSK fetched for another key belongs to another device
// peer and is never returned.
func (s *EdgePSKs) Lookup(peerNodeID, publicKey string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[peerNodeID]
	if e == nil || e.publicKey != publicKey {
		return nil, false
	}
	return slices.Clone(e.key[:]), true
}

// InvalidateAll marks every PSK stale, so the next Sync fetches each peer's
// again. plexd calls it once its own key rotation committed.
func (s *EdgePSKs) InvalidateAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		e.stale = true
	}
	s.gen++
}

// EdgePSKDispatchHandler returns a reconcile.DispatchHandler that syncs s
// against the peers of every successful pull. Dispatch handlers run before the
// reconcile handlers, so a new peer's PSK is fetched before the WireGuard
// handler adds the peer in the same cycle.
func EdgePSKDispatchHandler(s *EdgePSKs) reconcile.DispatchHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil {
			return
		}
		s.Sync(ctx, desired.Peers)
	}
}

// Sync brings the PSKs in line with peers: it forgets peers that left, fetches
// the PSK of every peer the re-fetch rule names, and installs every PSK the
// installer has not accepted yet. It never returns an error: a failed fetch is
// logged and retried on the next pull, and an older control plane sees at most
// one request per pull.
func (s *EdgePSKs) Sync(ctx context.Context, peers []api.SnapshotPeer) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.prune(peers)
	if s.now().Before(s.retryAt) {
		s.mu.Unlock()
		return
	}
	fetch := s.due(peers)
	gen := s.gen
	s.mu.Unlock()

	for _, p := range fetch {
		if !s.fetch(ctx, p, gen) {
			break
		}
	}
	if ctx.Err() != nil {
		return
	}
	s.install()
}

// prune forgets the PSK and the epoch floor of every peer not in peers,
// zeroing the key. s.mu must be held.
func (s *EdgePSKs) prune(peers []api.SnapshotPeer) {
	present := make(map[string]bool, len(peers))
	for _, p := range peers {
		present[p.NodeID] = true
	}
	for id, e := range s.entries {
		if !present[id] {
			clear(e.key[:])
			delete(s.entries, id)
		}
	}
	for id := range s.floors {
		if !present[id] {
			delete(s.floors, id)
		}
	}
}

// due returns, in node-ID order, the peers whose PSK must be fetched: no PSK
// yet, one fetched for another public key, or a stale one. s.mu must be held.
func (s *EdgePSKs) due(peers []api.SnapshotPeer) []api.SnapshotPeer {
	var fetch []api.SnapshotPeer
	seen := make(map[string]bool, len(peers))
	for _, p := range peers {
		if p.NodeID == "" || seen[p.NodeID] {
			continue
		}
		seen[p.NodeID] = true
		e := s.entries[p.NodeID]
		if e == nil || e.publicKey != p.PublicKey || e.stale {
			fetch = append(fetch, p)
		}
	}
	slices.SortFunc(fetch, func(a, b api.SnapshotPeer) int {
		return strings.Compare(a.NodeID, b.NodeID)
	})
	return fetch
}

// fetch fetches, checks and stores one peer's PSK, and reports whether the pass
// goes on to the next peer. gen is the InvalidateAll count the pass started
// under.
func (s *EdgePSKs) fetch(ctx context.Context, p api.SnapshotPeer, gen uint64) bool {
	env, err := s.fetcher.FetchEdgePSK(ctx, s.nodeID, p.NodeID)
	if err != nil {
		return s.fetchFailed(ctx, p, err)
	}

	s.mu.Lock()
	recovered := s.notServed
	s.notServed = false
	floor := s.floors[p.NodeID]
	s.mu.Unlock()
	if recovered {
		s.logger.Info("wireguard: edge psk: control plane serves edge psks")
	}

	// The epoch is fixed-width UTC, so byte order is chronological order.
	if floor != "" && env.Epoch < floor {
		s.logger.Warn("wireguard: edge psk: refusing an envelope older than the epoch in force",
			"peer_id", p.NodeID,
		)
		return true
	}
	key, err := openEdgePSK(s.nsk, env, s.nodeID, p.NodeID)
	if err != nil {
		s.logger.Warn("wireguard: edge psk: open failed", "peer_id", p.NodeID, "error", err)
		return true
	}

	s.mu.Lock()
	if old := s.entries[p.NodeID]; old != nil {
		clear(old.key[:])
	}
	s.entries[p.NodeID] = &edgePSK{
		publicKey: p.PublicKey,
		epoch:     env.Epoch,
		key:       key,
		stale:     s.gen != gen,
	}
	if env.Epoch > s.floors[p.NodeID] {
		s.floors[p.NodeID] = env.Epoch
	}
	s.mu.Unlock()
	clear(key[:])

	s.logger.Info("wireguard: edge psk fetched", "peer_id", p.NodeID, "epoch", env.Epoch)
	return true
}

// fetchFailed classifies a failed fetch, logs it and reports whether the pass
// goes on to the next peer.
func (s *EdgePSKs) fetchFailed(ctx context.Context, p api.SnapshotPeer, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case api.IsEdgePSKNotServed(err):
		s.mu.Lock()
		first := !s.notServed
		s.notServed = true
		s.mu.Unlock()
		if first {
			s.logger.Info("wireguard: edge psk: control plane does not serve edge psks, retrying on later pulls",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
		}
		return false
	case isAPIErr && apiErr.StatusCode == http.StatusTooManyRequests:
		pause := max(apiErr.RetryAfter, minEdgePSKPause)
		s.mu.Lock()
		s.retryAt = s.now().Add(pause)
		s.mu.Unlock()
		s.logger.Warn("wireguard: edge psk: rate limited, pausing fetches", "retry_after", pause)
		return false
	case isAPIErr && apiErr.StatusCode == http.StatusForbidden:
		// The contract makes a 403 terminal: node_deregistered says this node
		// was revoked, and retrying would poll the control plane forever.
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		s.logger.Error("wireguard: edge psk: control plane refused this node, stopping edge psk fetches",
			"code", apiErr.Code,
		)
		return false
	case errors.As(err, new(*url.Error)):
		// A transport failure (a refused connection, a request timeout) would
		// meet every remaining peer the same way, and the fetches run before
		// the reconcile handlers: ending the pass bounds a hanging control
		// plane to one request timeout per pull instead of one per peer.
		s.logger.Warn("wireguard: edge psk: control plane unreachable, retrying on the next pull",
			"peer_id", p.NodeID,
			"error", err,
		)
		return false
	case isAPIErr && ((apiErr.StatusCode == http.StatusNotFound && apiErr.Code == "peer_not_found") ||
		(apiErr.StatusCode == http.StatusConflict && apiErr.Code == "psk_not_ready")):
		s.logger.Debug("wireguard: edge psk: not ready, retrying on the next pull",
			"peer_id", p.NodeID,
			"code", apiErr.Code,
		)
		return true
	default:
		s.logger.Warn("wireguard: edge psk: fetch failed", "peer_id", p.NodeID, "error", err)
		return true
	}
}

// install hands every PSK the installer has not accepted yet to it, in node-ID
// order, and marks the ones it accepted. A failure leaves the PSK to the next
// pull.
func (s *EdgePSKs) install() {
	type pending struct {
		nodeID, publicKey, epoch string
		key                      [edgePSKSize]byte
	}
	s.mu.Lock()
	var todo []pending
	for id, e := range s.entries {
		if !e.installed {
			todo = append(todo, pending{nodeID: id, publicKey: e.publicKey, epoch: e.epoch, key: e.key})
		}
	}
	s.mu.Unlock()
	slices.SortFunc(todo, func(a, b pending) int { return strings.Compare(a.nodeID, b.nodeID) })

	for i := range todo {
		p := &todo[i]
		err := s.installer.SetPeerPSK(p.nodeID, p.publicKey, p.key[:])
		clear(p.key[:])
		if err != nil {
			s.logger.Warn("wireguard: edge psk: install failed", "peer_id", p.nodeID, "error", err)
			continue
		}
		s.mu.Lock()
		if e := s.entries[p.nodeID]; e != nil && e.publicKey == p.publicKey && e.epoch == p.epoch {
			e.installed = true
		}
		s.mu.Unlock()
	}
}
