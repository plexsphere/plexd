package main

// securityFigures are the security- figures of the security and trust model guide.
var securityFigures = []func() *Figure{
	securityTrustChain,
	securityRegistration,
	securityKeyRotation,
	securitySigningKeyRotation,
}

// secParts are the two participants of the sequence diagrams of the
// security guide: plexd, the client, and the control plane.
func secParts(f *Figure) *seq {
	return f.sequence(
		seqPart{x: 120, r: roleAgent, lines: []Line{name("Client"), code("plexd")}},
		seqPart{x: 640, r: roleCore, lines: []Line{name("Control Plane")}},
	)
}

// securityTrustChain draws the chain of trust from the bootstrap token
// to the peer tunnels, for docs/guide/security.md (Trust Chain).
func securityTrustChain() *Figure {
	f := &Figure{Name: "security-trust-chain", Title: "The chain of trust from the bootstrap token to the peer tunnels"}
	const w, notes = 360.0, 470.0
	tok := f.box(roleSecret, spec{x: 0, y: 0, w: w, lines: []Line{
		name("Bootstrap Token"), body("BootstrapToken policy;"), body("single-use, short-lived by default"),
	}})
	cp := f.box(roleCore, spec{x: 0, y: tok.y + tok.h + 60, w: w, lines: []Line{name("Control Plane")}})
	id := f.box(roleAgent, spec{x: 0, y: cp.y + cp.h + 150, w: w, lines: []Line{name("Node Identity")}})
	tun := f.box(roleAgent, spec{x: 0, y: id.y + id.h + 60, w: w, lines: []Line{name("Peer Tunnels")}})
	f.arrow(flow, tok.bottom(), cp.top())
	f.arrow(flow, cp.bottom(), id.top())
	f.arrow(flow, id.bottom(), tun.top())

	sk := f.box(roleSecret, spec{x: notes, w: 220, lines: []Line{name("Signing Key")}})
	sk.y = (cp.y+cp.h+id.y)/2 - sk.h/2 + 10
	f.arrow(flow, pt{cp.cx(), sk.cy()}, sk.left())

	f.notePanel(notes, cp.y, 0, cp.right(),
		name("Trust anchor"), body("distributes public keys, PSKs, and its"), body("own Ed25519 signing public key"))
	f.notePanel(sk.x+sk.w+50, sk.y-6, 0, sk.right(),
		body("Verifies all SSE events"), body("+ session JWTs"))
	f.notePanel(notes, id.y, 0, id.right(),
		body("Public key bound to node ID and mesh IP"))
	f.notePanel(notes, tun.y, 0, tun.right(),
		body("WireGuard E2E encryption"), body("(private key stays local)"))
	return f
}

// securityRegistration draws the registration exchange, in which only
// the public key leaves the node, for docs/guide/security.md (Phase 1:
// Registration).
func securityRegistration() *Figure {
	f := &Figure{Name: "security-registration", Title: "Registration: only the public key leaves the node"}
	s := secParts(f)
	s.self(0, body("Generate Curve25519 keypair"))
	s.msg(call, 0, 1, code("POST /v1/register"), code("{project_id, resource_handle,"), code("bootstrap_token, nonce, public_key,"), code("requested_resource_id (optional)}"))
	s.self(1, body("Validate token (redemption under"), body("its BootstrapToken policy)"))
	s.self(1, body("Assign mesh IP from the"), body("Domain mesh CIDR"))
	s.self(1, body("Store public key"))
	s.self(1, body("Generate Node Secret Key (NSK)"))
	s.msg(secretFlow, 1, 0, code("{node_id, mesh_ip, signing_public_key,"), code("signing_key_id, nsk, peer_snapshot,"), code("domain_mesh_cidr}"))
	s.self(0, body("Build the bearer envelope from"), body("node ID and NSK, set it as auth token"))
	s.end()
	return f
}

// securityKeyRotation draws a WireGuard key rotation started by a
// rotate_keys event, for docs/guide/security.md (Phase 4: Key
// Rotation).
func securityKeyRotation() *Figure {
	f := &Figure{Name: "security-key-rotation", Title: "Rotating the WireGuard key of a node"}
	s := secParts(f)
	s.msg(publish, 1, 0, body("SSE: rotate_keys (signed)"))
	s.self(0, body("Verify signature"))
	s.self(0, body("Generate and stage new Curve25519 keypair"))
	s.msg(call, 0, 1, code("POST /v1/keys/rotate"), code("{new_public_key}"))
	s.self(1, body("Store new public key"))
	s.self(1, body("Generate new PSKs"))
	s.self(1, body("Push new key to all peers"))
	s.msg(reply, 1, 0, code("{rotation_id, kid, wrap_key_version}"))
	s.self(0, body("Swap private key on disk"), body("and WireGuard interface"))
	s.msg(call, 0, 1, code("GET /v1/nodes/{node_id}/state"), body("(reconcile)"))
	s.msg(reply, 1, 0, body("Updated peers"))
	s.msg(call, 0, 1, code("GET /v1/nodes/{node_id}/peers/"), code("{peer_node_id}/psk"), body("(each peer)"))
	s.msg(secretFlow, 1, 0, body("Edge PSK envelope"), body("(sealed under the NSK)"))
	s.end()
	return f
}

// securitySigningKeyRotation draws how a node picks up a rotated
// Domain signing key from its next state pull, for
// docs/guide/security.md (Signing Key Rotation).
func securitySigningKeyRotation() *Figure {
	f := &Figure{Name: "security-signing-key-rotation", Title: "Picking up a rotated signing key from the state pull"}
	s := secParts(f)
	s.note(1, body("Operator rotates the"), body("Domain's signing key"))
	s.msg(call, 0, 1, code("GET /v1/nodes/{node_id}/state"), body("(reconcile)"))
	s.msg(reply, 1, 0, code("{..., signing_key: {key_id, public_key}}"))
	s.self(0, body("Install as the only trusted key"), body("(no grace window)"))
	s.self(0, body("Persist to signing_public_key"), body("and identity.json"))
	s.end()
	return f
}
