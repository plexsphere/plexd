package main

// DECISION: text is measured with the advance widths of DejaVu Sans,
// not of IBM Plex Sans, the family the figures name first. An SVG
// embedded with <img> loads no web fonts, so a reader sees whatever
// sans-serif the browser has: IBM Plex Sans where installed, Arial or
// Helvetica on most desktops, DejaVu Sans on many Linux systems.
// DejaVu Sans is the widest of these, so a box sized for it fits every
// other family with room to spare. Measuring with Plex instead would
// let labels overflow their boxes on exactly the systems that lack it.

// dejaVuRegular and dejaVuBold hold the advance width of the printable
// ASCII characters U+0020 to U+007E in em, read from the hmtx tables
// of DejaVuSans.ttf and DejaVuSans-Bold.ttf.
var dejaVuRegular = [95]float64{
	0.3179, 0.4009, 0.46, 0.8379, 0.6362, 0.9502, 0.7798, 0.2749, 0.3901, 0.3901,
	0.5, 0.8379, 0.3179, 0.3608, 0.3179, 0.3369, 0.6362, 0.6362, 0.6362, 0.6362,
	0.6362, 0.6362, 0.6362, 0.6362, 0.6362, 0.6362, 0.3369, 0.3369, 0.8379, 0.8379,
	0.8379, 0.5308, 1.0, 0.6841, 0.686, 0.6982, 0.77, 0.6318, 0.5752, 0.7749,
	0.752, 0.2949, 0.2949, 0.6558, 0.5571, 0.8628, 0.748, 0.7871, 0.603, 0.7871,
	0.6948, 0.6348, 0.6108, 0.7319, 0.6841, 0.9888, 0.6851, 0.6108, 0.6851, 0.3901,
	0.3369, 0.3901, 0.8379, 0.5, 0.5, 0.6128, 0.6348, 0.5498, 0.6348, 0.6152,
	0.3521, 0.6348, 0.6338, 0.2778, 0.2778, 0.5791, 0.2778, 0.9741, 0.6338, 0.6118,
	0.6348, 0.6348, 0.4111, 0.521, 0.3921, 0.6338, 0.5918, 0.8179, 0.5918, 0.5918,
	0.5249, 0.6362, 0.3369, 0.6362, 0.8379,
}

var dejaVuBold = [95]float64{
	0.3481, 0.4561, 0.521, 0.8379, 0.6958, 1.002, 0.8721, 0.3062, 0.457, 0.457,
	0.5229, 0.8379, 0.3799, 0.415, 0.3799, 0.3652, 0.6958, 0.6958, 0.6958, 0.6958,
	0.6958, 0.6958, 0.6958, 0.6958, 0.6958, 0.6958, 0.3999, 0.3999, 0.8379, 0.8379,
	0.8379, 0.5801, 1.0, 0.7739, 0.7622, 0.7339, 0.8301, 0.6831, 0.6831, 0.8208,
	0.8369, 0.3721, 0.3721, 0.7749, 0.6372, 0.9951, 0.8369, 0.8501, 0.7329, 0.8501,
	0.77, 0.7202, 0.6821, 0.812, 0.7739, 1.103, 0.771, 0.7241, 0.7251, 0.457,
	0.3652, 0.457, 0.8379, 0.5, 0.5, 0.6748, 0.7158, 0.5928, 0.7158, 0.6782,
	0.4351, 0.7158, 0.7119, 0.3428, 0.3428, 0.665, 0.3428, 1.042, 0.7119, 0.687,
	0.7158, 0.7158, 0.4932, 0.5952, 0.478, 0.7119, 0.6519, 0.9238, 0.645, 0.6519,
	0.582, 0.7119, 0.3652, 0.7119, 0.8379,
}

// monoAdvance is the advance width of every glyph of a monospaced
// family in em. DejaVu Sans Mono, Menlo and IBM Plex Mono all sit at
// 0.6; Consolas is narrower.
const monoAdvance = 0.6021

// lineHeight is the height of one line as a multiple of its font
// size. draw.io renders an HTML label with a CSS line-height of 1.2,
// and the SVG export spaces its lines the same way.
const lineHeight = 1.2

// advance returns the width of r in em for the given style.
func advance(r rune, bold, mono bool) float64 {
	if mono {
		return monoAdvance
	}
	if r >= 0x20 && r <= 0x7e {
		if bold {
			return dejaVuBold[r-0x20]
		}
		return dejaVuRegular[r-0x20]
	}
	switch r {
	case '·', '•':
		return 0.38
	case '→', '←', '↑', '↓', '↔', '≤', '≥', '≠', '×', '∈', '∅':
		return 0.84
	case '—', '…':
		return 1.0
	case '–':
		return 0.5
	case '‘', '’':
		return 0.32
	case '“', '”':
		return 0.52
	}
	return 0.7
}

// textWidth returns the width of one line in pixels.
func textWidth(l Line) float64 {
	w := 0.0
	for _, r := range l.Text {
		w += advance(r, l.Bold, l.Mono)
	}
	return w * l.Size
}

// blockSize returns the width of the widest line and the height of
// all lines stacked.
func blockSize(lines []Line) (w, h float64) {
	for _, l := range lines {
		w = max(w, textWidth(l))
		h += l.Size * lineHeight
	}
	return w, h
}
