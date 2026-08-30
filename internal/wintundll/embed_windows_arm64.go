//go:build windows && arm64

package wintundll

import _ "embed"

// dll is wintun/bin/arm64/wintun.dll from wintun-0.14.1.zip, unmodified.
// One architecture is embedded per binary, so an amd64 build never carries the
// arm64 driver.
//
//go:embed wintun_arm64.dll
var dll []byte
