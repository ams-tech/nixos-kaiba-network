package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt"
)

const maximumConfirmationBytes = 512

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-lane-operator: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet("kaiba-provision-lane-operator", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	socketPath := flags.String("socket", "", "fixed private lane operator Unix socket")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *socketPath == "" {
		return errors.New("socket is required")
	}

	client, err := operatorprompt.Connect(ctx, *socketPath)
	if err != nil {
		return err
	}
	defer client.Close()
	prompt := client.Prompt()
	phrase, err := operatorprompt.ConfirmationPhrase(prompt)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Physical lane operator acknowledgement required")
	fmt.Fprintf(output, "Station/lane: %s / %s\n", prompt.Action.StationID, prompt.Action.LaneID)
	fmt.Fprintf(output, "Transaction: %s\n", prompt.Action.TransactionID)
	fmt.Fprintf(output, "Operation: %s (sequence %d)\n", prompt.Action.Operation, prompt.Action.Sequence)
	fmt.Fprintf(output, "Phase/mode: %s / %s\n", prompt.Action.Phase, prompt.Action.RequestedBootMode)
	fmt.Fprintf(output, "Prompt kind: %s\n", prompt.Kind)
	fmt.Fprintf(output, "Instructions: %s\n", prompt.Instructions)
	fmt.Fprintf(output, "Prompt ID: %s\n", prompt.ID)
	fmt.Fprintf(output, "Prompt digest: %s\n", prompt.Digest)
	fmt.Fprintf(output, "Expires: %s\n", prompt.ExpiresAt.Format("2006-01-02T15:04:05.000000000Z07:00"))
	fmt.Fprintf(output, "Type exactly: %s\n> ", phrase)

	reader := bufio.NewReader(io.LimitReader(input, maximumConfirmationBytes+1))
	confirmation, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("read confirmation: %w", readErr)
	}
	if len(confirmation) == 0 || len(confirmation) > maximumConfirmationBytes {
		return errors.New("confirmation is empty or too long")
	}
	confirmation = strings.TrimSuffix(confirmation, "\n")
	if confirmation != phrase {
		return errors.New("typed confirmation did not exactly match the displayed prompt binding")
	}

	acknowledgement, err := client.Acknowledge(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Acknowledged at %s as peer uid=%d gid=%d pid=%d\n",
		acknowledgement.AcknowledgedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
		acknowledgement.Peer.UID, acknowledgement.Peer.GID, acknowledgement.Peer.PID)
	return nil
}
