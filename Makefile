.PHONY: build test test-e2e test-e2e-docker test-e2e-k8s test-e2e-systemd lint vet docker-build upgrade-fixture

build:
	go build ./...

test:
	go test -race -count=1 ./...

test-e2e:
	go test -race -count=1 -run Integration ./...

test-e2e-docker:
	bash test/e2e/docker/test.sh

test-e2e-k8s:
	bash test/e2e/kubernetes/test.sh

test-e2e-systemd:
	bash test/e2e/systemd/test.sh

lint: vet
	golangci-lint run

vet:
	go vet ./...

docker-build:
	docker build -f deploy/docker/Dockerfile \
		--build-arg VERSION=$(shell git describe --tags --always 2>/dev/null || echo dev) \
		--build-arg COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo none) \
		--build-arg DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t ghcr.io/plexsphere/plexd:dev .

# upgrade-fixture regenerates the Sigstore verification fixture used by the
# internal/upgrade tests (and, in a later step, the e2e mock API).
#
# Provenance of the CHECKED-IN fixture (not produced by this target): the blob
# is test/assets/bundle-verify/a.txt and the bundle is
# test/assets/bundle-verify/happy-path-v0.3/bundle.sigstore.json from
# github.com/sigstore/sigstore-conformance (branch main). That bundle is a
# real keyless message-signature signed against the Sigstore public-good
# production instance by the conformance OIDC beacon, so it verifies offline
# against internal/upgrade/trusted_root.json. internal/upgrade/trusted_root.json
# was vendored from the sigstore-go module,
# examples/trusted-root-public-good.json (github.com/sigstore/sigstore-go
# v1.2.2), which is byte-identical to that module's own public-good test root.
#
# This target documents how a plexd maintainer produces a FRESH fixture signed
# under the plexd release identity. It needs cosign >= v3 (new v0.3 bundle
# format) and performs an interactive OIDC browser login, so it is not run in
# CI. After running it, the printed SAN/issuer must be reflected in the
# upgrade.signing_identity_regexp / signing_issuer knobs (see the echo below).
upgrade-fixture:
	printf 'plexd upgrade verification fixture\n' > internal/upgrade/testdata/fixture.bin
	# cosign >= v3 keyless sign-blob; opens a browser for OIDC. Produces a v0.3
	# Sigstore bundle over the exact blob bytes.
	cosign sign-blob --yes \
		--bundle internal/upgrade/testdata/fixture.sigstore.json \
		internal/upgrade/testdata/fixture.bin
	# Keep the e2e mock API's copy in lock-step with the unit-test fixture. The
	# destination directory is created by a later work package; the cp commands
	# document the coupling regardless.
	mkdir -p test/e2e/mockapi/testdata
	cp internal/upgrade/testdata/fixture.bin test/e2e/mockapi/testdata/fixture.bin
	cp internal/upgrade/testdata/fixture.sigstore.json test/e2e/mockapi/testdata/fixture.sigstore.json
	# Print the leaf certificate SAN (signing identity) and issuer so they can be
	# copied into the upgrade config. rawBytes is the base64 DER leaf cert.
	@echo "--- signing identity (SAN) ---"
	jq -r '.verificationMaterial.certificate.rawBytes // .verificationMaterial.x509CertificateChain.certificates[0].rawBytes' \
		internal/upgrade/testdata/fixture.sigstore.json \
		| base64 -d | openssl x509 -inform der -noout -ext subjectAltName
	@echo "--- issuer (OID 1.3.6.1.4.1.57264.1.1) ---"
	jq -r '.verificationMaterial.certificate.rawBytes // .verificationMaterial.x509CertificateChain.certificates[0].rawBytes' \
		internal/upgrade/testdata/fixture.sigstore.json \
		| base64 -d | openssl x509 -inform der -noout -text \
		| grep -A1 '1.3.6.1.4.1.57264.1.1:'
	@echo
	@echo "NOTE: test/e2e/docker/plexd-e2e.yaml's upgrade.signing_identity_regexp"
	@echo "      and upgrade.signing_issuer must be updated together with these"
	@echo "      fixture files to match the SAN/issuer printed above."
	@echo "NOTE: internal/upgrade/trusted_root.json is vendored from sigstore-go"
	@echo "      examples/trusted-root-public-good.json; refresh it from"
	@echo "      https://tuf-repo-cdn.sigstore.dev (target trusted_root.json) if a"
	@echo "      newer fixture needs key material not present in the vendored root."
