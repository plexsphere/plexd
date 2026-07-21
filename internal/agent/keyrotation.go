package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/registration"
)

// RotateClient submits a completed rotation's public key to the control plane.
type RotateClient interface {
	RotateKeys(ctx context.Context, req api.KeyRotateRequest) (*api.KeyRotateResponse, error)
}

// DeviceKeyUpdater installs a rotated private key on the WireGuard device.
type DeviceKeyUpdater interface {
	UpdatePrivateKey(privateKey []byte) error
}

const (
	recoverInitialBackoff = 5 * time.Second
	recoverMaxBackoff     = 2 * time.Minute

	// minRotationInterval is the floor between two rotations the repeated
	// heartbeat rotate_keys flag starts. The control plane keeps that flag set
	// until it observes the new key and the heartbeat repeats it every
	// interval, so a lagging observation would otherwise rekey the device on
	// every heartbeat and flap every peer session in between. The one-shot SSE
	// rotate_keys event bypasses the floor via RotateNow.
	minRotationInterval = 5 * time.Minute

	// deviceInstallAttempts and deviceInstallBackoff bound the retry of the
	// device key install after a commit. Doubling from a second, the attempts
	// span roughly two minutes: the commit is already durable and every peer
	// already holds the new public key, so the window has to outlast a device
	// that is briefly unusable (fd exhaustion, a netlink stall, a concurrent
	// interface reconfiguration) rather than just a single failed call. Nothing
	// retries afterwards, so a short window buys nothing back.
	deviceInstallAttempts = 8
	deviceInstallBackoff  = time.Second
)

// KeyRotator runs the mesh-key rotation state machine. Both rotation signals
// drive the same single-flight cycle: the repeated heartbeat rotate_keys flag
// through Rotate, which rate-limits fresh starts, and the one-shot SSE
// rotate_keys event through RotateNow, which does not. The control plane keeps
// a rotation pending until the node confirms it, so repeated signals, retries,
// and the RecoverPending sweep all converge on the same crash-safe outcome.
type KeyRotator struct {
	client  RotateClient
	id      *registration.NodeIdentity
	dataDir string
	device  DeviceKeyUpdater
	rt      ReconcileTrigger
	logger  *slog.Logger

	// mu enforces single-flight rotation: the heartbeat repeats the flag every
	// interval and the flag can arrive alongside the SSE event, so overlapping
	// Rotate calls return immediately instead of racing on the staging file.
	mu sync.Mutex

	// recoverInitial and recoverMax bound RecoverPending's backoff, deviceDelay
	// the device-install retry, minInterval the rotation cooldown. They are
	// seeded from the package consts and only shrunk by same-package tests.
	recoverInitial time.Duration
	recoverMax     time.Duration
	deviceDelay    time.Duration
	minInterval    time.Duration

	// lastCommit is when the most recent rotation committed; it gates the
	// cooldown and is read and written under mu.
	lastCommit time.Time
}

// NewKeyRotator builds a KeyRotator that stages fresh keys under dataDir,
// submits their public half via client, installs the confirmed private key on
// device (may be nil), and triggers a reconcile through rt once a rotation
// commits.
func NewKeyRotator(client RotateClient, id *registration.NodeIdentity, dataDir string, device DeviceKeyUpdater, rt ReconcileTrigger, logger *slog.Logger) *KeyRotator {
	return &KeyRotator{
		client:         client,
		id:             id,
		dataDir:        dataDir,
		device:         device,
		rt:             rt,
		logger:         logger.With("component", "keyrotation"),
		recoverInitial: recoverInitialBackoff,
		recoverMax:     recoverMaxBackoff,
		deviceDelay:    deviceInstallBackoff,
		minInterval:    minRotationInterval,
	}
}

// Rotate runs one single-flight rotation cycle. It stages a fresh key (or
// reuses one staged by an earlier attempt), submits its public half, and
// commits the durable identity only after the control plane confirms. A
// concurrent Rotate that loses the TryLock returns nil without touching the
// staging file, and starting a fresh rotation within minInterval of the last
// commit is skipped; a key already staged is always resubmitted. The outcome
// taxonomy over the submit result is:
//   - success with a complete receipt: commit with the returned receipt;
//   - success without a receipt: a control plane that predates this contract, so
//     keep the staged key for a resubmit and return the error;
//   - 422 keys_rotate_public_key_unchanged: a previous submission already
//     landed (a crash between submit and persist), so commit with a nil
//     receipt to keep the existing LastRotation;
//   - 409 keys_rotate_no_pending_rotation: a stale or cancelled signal whose
//     staged key never landed, so discard it and return nil;
//   - a permanent rejection (400, 403, 413, 404 keys_rotate_peer_not_found,
//     422 keys_rotate_public_key_invalid): no retry changes the outcome, so
//     discard the staged key and return the error;
//   - anything else (auth, 5xx, transport errors): keep the staged key so
//     RecoverPending or the next signal retries, and return the error.
func (r *KeyRotator) Rotate(ctx context.Context) error {
	return r.rotate(ctx, false)
}

// RotateNow runs the same rotation cycle as Rotate but starts a fresh rotation
// even within minInterval of the last commit. It serves the SSE rotate_keys
// event: the control plane sends it once per rotation decision and never
// repeats it, so a cooldown skip here would strand the rotation until the
// heartbeat flag catches up — or forever, for a control plane that signals via
// SSE alone. A redelivered event is harmless: with no rotation pending the
// submit is answered 409 keys_rotate_no_pending_rotation and the staged key is
// discarded without touching the device.
func (r *KeyRotator) RotateNow(ctx context.Context) error {
	return r.rotate(ctx, true)
}

func (r *KeyRotator) rotate(ctx context.Context, bypassCooldown bool) error {
	if !r.mu.TryLock() {
		r.logger.DebugContext(ctx, "agent: key rotation: already in flight")
		return nil
	}
	defer r.mu.Unlock()

	kp, err := registration.LoadPendingKey(r.dataDir)
	if err != nil {
		// An unreadable staging file (a truncated write, a partial copy of the
		// data dir) would otherwise wedge rotation for good: every Rotate returns
		// here before touching the network and RecoverPending replays the same
		// read forever. The staged key is recoverable state, not an identity, so
		// discard it and stage a fresh one.
		r.logger.WarnContext(ctx, "agent: key rotation: discarded an unreadable staged rotation key", "error", err)
		if cerr := registration.ClearPendingKey(r.dataDir); cerr != nil {
			return cerr
		}
	}
	if kp == nil {
		if !bypassCooldown {
			if since := time.Since(r.lastCommit); since < r.minInterval {
				r.logger.InfoContext(ctx, "agent: key rotation: skipped, the last rotation committed less than the minimum interval ago",
					"since", since, "min_interval", r.minInterval)
				return nil
			}
		}
		kp, err = registration.GenerateKeypair()
		if err != nil {
			return err
		}
		if err := registration.SavePendingKey(r.dataDir, kp); err != nil {
			return err
		}
		r.logger.InfoContext(ctx, "agent: key rotation: staged a fresh rotation key")
	} else {
		r.logger.InfoContext(ctx, "agent: key rotation: reusing the staged rotation key")
	}

	resp, err := r.client.RotateKeys(ctx, api.KeyRotateRequest{NewPublicKey: kp.EncodePublicKey()})
	if err == nil {
		// The response body is decoded leniently, so a control plane still on a
		// pre-v1 contract answers 200 with fields this receipt does not carry.
		// Persisting the zero receipt would record a rotation that proves
		// nothing; keep the staged key instead so a resubmit succeeds once the
		// server speaks the v1 contract.
		if resp.RotationID == "" || resp.KID == "" {
			return fmt.Errorf("agent: key rotation: control plane returned an incomplete receipt (rotation_id=%q kid=%q)", resp.RotationID, resp.KID)
		}
		return r.commit(ctx, kp, &registration.RotationReceipt{
			RotationID:     resp.RotationID,
			KID:            resp.KID,
			WrapKeyVersion: resp.WrapKeyVersion,
		})
	}

	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == 422 && apiErr.Code == "keys_rotate_public_key_unchanged":
			// The public half already reached the control plane; the process
			// died before persisting the commit. Re-commit locally with a nil
			// receipt so the previous LastRotation is preserved.
			r.logger.InfoContext(ctx, "agent: key rotation: control plane reports the public key unchanged, committing the already-accepted rotation")
			return r.commit(ctx, kp, nil)
		case apiErr.StatusCode == 409 && apiErr.Code == "keys_rotate_no_pending_rotation":
			// A stale or cancelled signal: the staged key was never accepted, so
			// drop it and wait for a fresh rotation.
			if cerr := registration.ClearPendingKey(r.dataDir); cerr != nil {
				return cerr
			}
			r.logger.WarnContext(ctx, "agent: key rotation: control plane reports no pending rotation, discarded the staged key")
			return nil
		case apiErr.StatusCode == 422 && apiErr.Code == "keys_rotate_public_key_invalid",
			apiErr.StatusCode == 404 && apiErr.Code == "keys_rotate_peer_not_found",
			apiErr.StatusCode == 400,
			apiErr.StatusCode == 403,
			apiErr.StatusCode == 413:
			// Permanent rejections: an invalid or oversized body and a denied or
			// unknown node all stay rejected however often the same key is
			// resubmitted. Discard the staged key so RecoverPending and every
			// later signal stop replaying it, and surface the rejection.
			if cerr := registration.ClearPendingKey(r.dataDir); cerr != nil {
				return cerr
			}
			r.logger.ErrorContext(ctx, "agent: key rotation: control plane rejected the rotation permanently, discarded the staged key",
				"status", apiErr.StatusCode, "code", apiErr.Code, "error", err)
			return err
		}
	}

	// Auth, 5xx, and transport errors leave the outcome unknown: the rotation
	// may still be pending server-side, or it may have committed there with the
	// response lost on the way back. Keep the staged key — RecoverPending
	// resubmits it until it lands, because a rotation the control plane already
	// completed is never signalled again.
	return err
}

// commit performs the post-confirmation swap: it durably installs kp, arms the
// rotation cooldown, updates the WireGuard device, and triggers a reconcile so
// the propagated peer view arrives via the normal state pull. A device error is returned but does not
// abort — the durable identity is already swapped, and the committed key is
// what a fresh interface setup installs.
func (r *KeyRotator) commit(ctx context.Context, kp *registration.Keypair, receipt *registration.RotationReceipt) error {
	if err := registration.CommitRotatedKey(r.dataDir, r.id, kp, receipt); err != nil {
		return err
	}
	r.lastCommit = time.Now()

	var devErr error
	if r.device != nil {
		devErr = r.installDeviceKey(ctx, kp.PrivateKey)
	}

	r.rt.TriggerReconcile()

	return devErr
}

// installDeviceKey installs the committed private key on the WireGuard device,
// retrying a transient failure with an exponential backoff until the attempts
// are exhausted or ctx is cancelled. The retry is what keeps a
// hiccup here from stranding the node: private_key on disk has already been
// swapped and the control plane has published the new public key to every peer,
// so a device left on the old key rejects every handshake, and no further
// rotation signal arrives to fix it. A failure that outlives the retries is
// logged at ERROR and returned; recovering from it needs a fresh interface
// setup, which installs the committed key.
func (r *KeyRotator) installDeviceKey(ctx context.Context, privateKey []byte) error {
	delay := r.deviceDelay
	for attempt := 1; ; attempt++ {
		err := r.device.UpdatePrivateKey(privateKey)
		if err == nil {
			return nil
		}
		if attempt == deviceInstallAttempts {
			r.logger.ErrorContext(ctx, "agent: key rotation: failed to install the rotated key on the device, the node stays off the mesh until the interface is set up again",
				"attempts", attempt, "error", err)
			return err
		}
		r.logger.WarnContext(ctx, "agent: key rotation: installing the rotated key on the device failed, retrying",
			"attempt", attempt, "error", err)

		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// RecoverPending drives staged-but-uncommitted rotations for the lifetime of
// ctx. A staged key that the control plane already accepted strands the node
// unless something resubmits it: the rotation completed server-side, so no
// further signal arrives, every peer holds the new public key, and the node
// still runs the old one. That state outlives startup — a submit whose response
// is lost (proxy 5xx, read timeout, reset connection) leaves exactly the same
// staged key at any point during the process lifetime — so this loop keeps
// sweeping instead of returning once nothing is staged.
//
// While a key is staged it resubmits with a capped exponential backoff; with
// nothing staged it re-checks at the cap and makes no HTTP call, so an idle
// node never starts a rotation on its own.
func (r *KeyRotator) RecoverPending(ctx context.Context) {
	delay := r.recoverInitial
	for {
		wait := r.recoverMax // idle sweep cadence
		kp, err := registration.LoadPendingKey(r.dataDir)
		if err != nil || kp != nil {
			// Either a key is staged or the staging file is unreadable. Rotate
			// re-reads it and drives the outcome; an unreadable staging file is
			// discarded there and replaced by a fresh one.
			if rerr := r.Rotate(ctx); rerr != nil {
				// Without this line a control plane that keeps failing the
				// resubmit leaves the node retrying forever with no
				// operator-visible signal.
				r.logger.WarnContext(ctx, "agent: key rotation: resubmitting the staged rotation failed, retrying",
					"delay", delay, "error", rerr)
			}
			wait = delay
			if delay *= 2; delay > r.recoverMax {
				delay = r.recoverMax
			}
		} else {
			// Nothing staged: rearm the backoff so the next rotation that needs
			// recovering is resubmitted promptly.
			delay = r.recoverInitial
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
