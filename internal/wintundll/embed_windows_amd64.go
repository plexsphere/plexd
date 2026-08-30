//go:build windows && amd64

package wintundll

import _ "embed"

// dll is wintun/bin/amd64/wintun.dll from wintun-0.14.1.zip, unmodified.
// One architecture is embedded per binary, so an arm64 build never carries the
// x64 driver.
//
//go:embed wintun_amd64.dll
var dll []byte
