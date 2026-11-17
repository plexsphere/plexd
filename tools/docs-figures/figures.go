package main

// figureGroups lists the figure functions of every fig_*.go file, in
// the order of the inventory in docs/reference/development/diagrams.md.
// Each file declares its own group, so a figure is added by appending
// its function to the group of its file.
func figureGroups() [][]func() *Figure {
	return [][]func() *Figure{
		architectureFigures,
		communicationFigures,
		securityFigures,
		coreFigures,
		actionsFigures,
		bridgeFigures,
		bridgeAccessFigures,
		networkingFigures,
		developmentFigures,
		conventionsFigures,
	}
}

// allFigures returns every figure the tool draws, in the order of the
// inventory.
func allFigures() []*Figure {
	var figs []*Figure
	for _, group := range figureGroups() {
		for _, fn := range group {
			figs = append(figs, fn())
		}
	}
	return figs
}
