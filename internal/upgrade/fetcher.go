package upgrade

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
)

// maxBundleBytes caps the Sigstore bundle download so a hostile mirror cannot
// balloon memory. Bundles are a few KiB; 8 MiB is a generous ceiling.
const maxBundleBytes = 8 << 20

// maxBinaryBytes caps the release binary download so a hostile mirror cannot
// exhaust the disk of the partition holding the plexd binary. Real assets are
// tens of MiB; 512 MiB is a generous ceiling. It is a var so tests can lower it.
var maxBinaryBytes int64 = 512 << 20

// versionPattern matches an accepted release version: semantic-version digits
// with an optional "v" prefix and an optional pre-release suffix. It rejects any
// value carrying a path separator or other characters that could escape the
// release path once interpolated into the download URL.
var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// goos is a test seam for runtime.GOOS. Releases ship Linux assets only, so the
// fetcher refuses to download on other platforms.
var goos = runtime.GOOS

// Fetcher downloads plexd release assets from the GitHub release channel.
type Fetcher struct {
	baseURL string
	client  *http.Client
}

// NewFetcher creates a Fetcher for the given configuration.
func NewFetcher(cfg Config) *Fetcher {
	return &Fetcher{
		baseURL: strings.TrimRight(cfg.ReleaseBaseURL, "/"),
		client:  &http.Client{},
	}
}

// releaseTag returns the git tag for a version, prefixing "v" only when absent.
func releaseTag(version string) string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

// assetName returns the release asset file name for the current architecture.
func assetName() string {
	return "plexd-linux-" + runtime.GOARCH
}

// FetchBinary downloads the plexd binary for the given version and returns its
// body, capped at maxBinaryBytes so a hostile mirror cannot fill the disk before
// the checksum is verified. The caller must close the returned reader.
func (f *Fetcher) FetchBinary(ctx context.Context, version string) (io.ReadCloser, error) {
	asset := assetName()
	resp, err := f.get(ctx, version, asset)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, maxBinaryBytes), resp.Body}, nil
}

// FetchBundle downloads the Sigstore bundle for the given version. The body is
// read through an io.LimitReader capped at maxBundleBytes.
func (f *Fetcher) FetchBundle(ctx context.Context, version string) ([]byte, error) {
	asset := assetName() + ".sigstore.json"
	resp, err := f.get(ctx, version, asset)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes))
	if err != nil {
		return nil, fmt.Errorf("read release asset %s: %w", asset, err)
	}
	return data, nil
}

// get performs the GET for a release asset. It refuses non-Linux platforms
// before any network I/O and returns a non-nil response only on HTTP 200; the
// caller owns the returned body.
func (f *Fetcher) get(ctx context.Context, version, asset string) (*http.Response, error) {
	if goos != "linux" {
		return nil, fmt.Errorf("download release asset %s: releases ship linux assets only, running on %s", asset, goos)
	}

	if !versionPattern.MatchString(version) {
		return nil, fmt.Errorf("download release asset %s: invalid version %q", asset, version)
	}

	url := fmt.Sprintf("%s/%s/%s", f.baseURL, releaseTag(version), asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for release asset %s: %w", asset, err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("download release asset: %w", ctx.Err())
		}
		return nil, fmt.Errorf("download release asset %s: %w", asset, err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download release asset %s: unexpected status %d", asset, resp.StatusCode)
	}
	return resp, nil
}
