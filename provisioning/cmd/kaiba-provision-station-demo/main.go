package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stationui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-station-demo: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("kaiba-provision-station-demo", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listen := flags.String("listen", "127.0.0.1:8080", "explicit loopback IP address and port")
	scenario := flags.String("scenario", string(stationui.ScenarioHappyPath), "fixed mock scenario")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := stationui.ValidateListenAddress(*listen); err != nil {
		return err
	}
	machine, err := stationui.NewMockMachine(stationui.ScenarioID(*scenario))
	if err != nil {
		return err
	}
	return stationui.ListenAndServe(ctx, *listen, machine, stationui.EmbeddedAssets())
}
