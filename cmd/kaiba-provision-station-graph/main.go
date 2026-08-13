package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kaiba-network/dns-pilot/internal/provisioning/stationui"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: kaiba-provision-station-graph")
		os.Exit(2)
	}
	graph, err := stationui.GenerateTransitionGraph()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-station-graph: %v\n", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(graph); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-station-graph: encode: %v\n", err)
		os.Exit(1)
	}
}
