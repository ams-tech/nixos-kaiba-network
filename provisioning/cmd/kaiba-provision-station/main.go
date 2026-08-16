package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/livestation"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-station: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("kaiba-provision-station", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listen := flags.String("listen", "127.0.0.1:8081", "explicit loopback IP address and port")
	stationID := flags.String("station-id", "development-station", "fixed station identity")
	laneID := flags.String("lane-id", "lane-1", "fixed lane identity")
	usbPath := flags.String("rpiboot-sysfs", "/sys/bus/usb/devices/1-1", "fixed RPIBOOT sysfs path")
	uartPath := flags.String("uart", "/dev/serial/by-id/kaiba-target-uart", "fixed target UART path")
	enableMutations := flags.Bool("enable-mutations", false, "enable an explicitly installed hardware orchestration backend")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := livestation.ValidateListenAddress(*listen); err != nil {
		return err
	}
	if *enableMutations {
		return errors.New("mutation was requested, but this foundation build has no installed hardware orchestration backend")
	}
	machine, err := livestation.NewMachine(livestation.Config{
		StationID: *stationID, LaneID: *laneID, USBPath: *usbPath, UARTPath: *uartPath,
		MutationCapable: false,
	}, livestation.DisabledBackend{Reason: "install and explicitly enable the production orchestration backend"})
	if err != nil {
		return err
	}
	return livestation.ListenAndServe(ctx, *listen, machine)
}
