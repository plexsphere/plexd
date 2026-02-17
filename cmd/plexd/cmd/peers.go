package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List mesh peers",
	Long:  "Connect to the local agent via Unix socket and list mesh peers.",
	RunE:  runPeers,
}

func init() {
	rootCmd.AddCommand(peersCmd)
}

type peerStatus struct {
	ID       string `json:"id"`
	PublicKey string `json:"public_key"`
	MeshIP   string `json:"mesh_ip"`
	Endpoint string `json:"endpoint"`
}

func runPeers(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/peers")
	if err != nil {
		return fmt.Errorf("plexd peers: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd peers: read response: %w", err)
	}

	var peers []peerStatus
	if err := json.Unmarshal(body, &peers); err != nil {
		return fmt.Errorf("plexd peers: parse response: %w", err)
	}

	if len(peers) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No peers connected.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PEER ID\tMESH IP\tENDPOINT\tPUBLIC KEY")
	for _, p := range peers {
		pubKey := p.PublicKey
		if len(pubKey) > 12 {
			pubKey = pubKey[:12] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.ID, p.MeshIP, p.Endpoint, pubKey)
	}
	w.Flush()
	return nil
}
