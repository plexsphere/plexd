package main

import (
	"math"
	"testing"
)

func TestTextWidthUsesTheWidestFallbackMetrics(t *testing.T) {
	t.Parallel()
	// "plexsphere" in DejaVu Sans at 20 px: the advance widths of its
	// ten glyphs, summed and scaled.
	want := (0.6348 + 0.2778 + 0.6152 + 0.5918 + 0.521 + 0.6348 + 0.6338 + 0.6152 + 0.4111 + 0.6152) * 20
	if got := textWidth(Line{Text: "plexsphere", Size: 20}); math.Abs(got-want) > 1e-9 {
		t.Errorf("textWidth = %v, want %v", got, want)
	}
}

func TestBoldIsWiderThanRegular(t *testing.T) {
	t.Parallel()
	regular := textWidth(Line{Text: "Registration Service", Size: 20})
	bold := textWidth(Line{Text: "Registration Service", Size: 20, Bold: true})
	if bold <= regular {
		t.Errorf("bold %v is not wider than regular %v", bold, regular)
	}
}

func TestMonoAdvanceIsConstant(t *testing.T) {
	t.Parallel()
	a := textWidth(Line{Text: "iiii", Size: 16, Mono: true})
	b := textWidth(Line{Text: "WWWW", Size: 16, Mono: true})
	if a != b || a != 4*monoAdvance*16 {
		t.Errorf("mono widths %v and %v, want both %v", a, b, 4*monoAdvance*16)
	}
}

func TestNonASCIIGlyphsHaveAWidth(t *testing.T) {
	t.Parallel()
	for _, r := range "→·…≤ä" {
		if advance(r, false, false) <= 0 {
			t.Errorf("advance(%q) is not positive", r)
		}
	}
}

func TestBlockSizeStacksLines(t *testing.T) {
	t.Parallel()
	w, h := blockSize([]Line{name("abc"), body("a much longer line")})
	if want := sizeName*lineHeight + sizeBody*lineHeight; h != want {
		t.Errorf("height %v, want %v", h, want)
	}
	if want := textWidth(body("a much longer line")); w != want {
		t.Errorf("width %v, want the widest line %v", w, want)
	}
}
