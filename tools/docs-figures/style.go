package main

// The palette and the type scale of every figure. The role table in
// docs/reference/development/diagrams.md (Visual conventions) is written from
// these values; a change here changes that table in the same commit.

const (
	colorBackground = "#F6F5F1"
	colorPaper      = "#FDFCF9"
	colorInk        = "#2B3440"
	colorInkDark    = "#17202B"
	colorMuted      = "#55606E"
	colorLine       = "#3A4452"
	colorGrey       = "#7D8794"
	colorFrameFill  = "#EEF0F3"
	colorGreyFill   = "#E9ECEF"
	colorWhiteText  = "#FBFAF7"
)

// role is the colour triple of one kind of thing in a figure: the
// outline, the text, and the light fill.
type role struct {
	stroke string
	text   string
	fill   string
}

var (
	// roleCore is the plexsphere control plane: its services and the
	// API plexd calls.
	roleCore = role{stroke: "#2457C5", text: "#1D47A6", fill: "#E7EDF9"}
	// roleAgent is plexd, its packages and subsystems, and the Nodes it
	// runs on: the data plane.
	roleAgent = role{stroke: "#2F8A57", text: "#1E6B40", fill: "#E6F1EA"}
	// roleStore is a store or state that persists: the data directory,
	// the state cache, a file on the Node, a database.
	roleStore = role{stroke: "#0E7D89", text: "#0B5F69", fill: "#E3F1F2"}
	// roleSecret is secret material and key custody: tokens, the NSK,
	// WireGuard and signing keys, session JWTs.
	roleSecret = role{stroke: "#B0387F", text: "#8A2B63", fill: "#F7E8F0"}
	// roleEvent is an event or a record on its way: SSE events,
	// callbacks, reports, log and audit records.
	roleEvent = role{stroke: "#B38A00", text: "#6F5600", fill: "#FAF3DA"}
	// roleExternal is a system plexd talks to but does not run: STUN
	// servers, an ACME CA, a VPN or tunnel provider, an identity provider.
	roleExternal = role{stroke: "#5E43A8", text: "#4B3592", fill: "#EEEAF7"}
	// roleSubstrate is the machine plexd runs on and its kernel: a
	// bare-metal server, a VM, a Kubernetes cluster, a bridge host,
	// netlink, nftables.
	roleSubstrate = role{stroke: "#C9620F", text: "#A44E07", fill: "#FBEFE3"}
	// roleFailure is a refusal, an error response or a failed state.
	roleFailure = role{stroke: "#C6343C", text: "#A3262E", fill: "#F8E8E9"}
	// roleNeutral is a platform package or anything without a role of
	// its own.
	roleNeutral = role{stroke: "#7D8794", text: "#2B3440", fill: "#EEF0F3"}
)

// The type scale. The figures are drawn for a canvas of about 1,100
// pixels that the docs site scales into its content column, so the
// smallest size stays legible at roughly two thirds of its value.
const (
	sizeHeading = 22.0 // frame titles
	sizeName    = 20.0 // the name of a box, a state, a participant
	sizeBody    = 17.0 // second lines, edge labels, notes
	sizeCode    = 16.0 // monospaced identifiers
	sizeChip    = 15.0 // chips and badges
	sizeCaption = 16.0 // captions under a figure
)

// Stroke widths.
const (
	strokeBox   = 2.0
	strokeArrow = 2.5
	strokeFrame = 2.0
	strokeLife  = 1.5
)

// The draw.io font settings. fontSource makes the draw.io editor load
// the family from Google Fonts; the SVG export names a fallback stack
// instead, because an image embedded with <img> loads no web fonts.
const (
	fontSans       = "IBM Plex Sans"
	fontMono       = "IBM Plex Mono"
	fontSourceSans = "https%3A%2F%2Ffonts.googleapis.com%2Fcss%3Ffamily%3DIBM%2BPlex%2BSans"
	svgFontSans    = "'IBM Plex Sans', Arial, Helvetica, sans-serif"
	svgFontMono    = "'IBM Plex Mono', Menlo, Consolas, 'DejaVu Sans Mono', monospace"
)

// margin is the empty border around the drawing on every side.
const margin = 40.0
