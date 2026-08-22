package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3
)

var (
	loadPlan                = mediacontract.LoadPlan
	loadStageReceipt        = mediacontract.LoadStageReceipt
	loadVerificationReceipt = mediacontract.LoadVerificationReceipt
	loadColdObservation     = mediacontract.LoadColdPowerObservation
	finalizeReceipts        = mediacontract.Finalize
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch arguments[0] {
	case "validate-plan":
		return validatePlanCommand(arguments[1:], stdout, stderr)
	case "validate-stage-receipt":
		return validateStageCommand(arguments[1:], stdout, stderr)
	case "validate-verification-receipt":
		return validateVerificationCommand(arguments[1:], stdout, stderr)
	case "finalize":
		return finalizeCommand(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func validatePlanCommand(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "absolute canonical plan path")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 || *planPath == "" {
		printUsage(stderr)
		return exitUsage
	}
	plan, err := loadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate media plan: %v\n", err)
		return exitInvalid
	}
	return encode(stdout, stderr, map[string]any{"status": "valid", "plan_digest": plan.PlanDigest})
}

func validateStageCommand(arguments []string, stdout, stderr io.Writer) int {
	flags, planPath, stagePath, _, _, parseCode := receiptFlags("validate-stage-receipt", arguments, stderr, false, false)
	if parseCode != -1 {
		return parseCode
	}
	_ = flags
	plan, err := loadPlan(planPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate media plan: %v\n", err)
		return exitInvalid
	}
	stage, err := loadStageReceipt(stagePath, plan)
	if err != nil {
		fmt.Fprintf(stderr, "validate stage receipt: %v\n", err)
		return exitInvalid
	}
	return encode(stdout, stderr, map[string]any{"status": "valid", "receipt_digest": stage.ReceiptDigest})
}

func validateVerificationCommand(arguments []string, stdout, stderr io.Writer) int {
	_, planPath, stagePath, verificationPath, _, parseCode := receiptFlags("validate-verification-receipt", arguments, stderr, true, false)
	if parseCode != -1 {
		return parseCode
	}
	plan, stage, verification, err := loadVerificationChain(planPath, stagePath, verificationPath)
	_ = plan
	_ = stage
	if err != nil {
		fmt.Fprintf(stderr, "validate verification receipt: %v\n", err)
		return exitInvalid
	}
	return encode(stdout, stderr, map[string]any{"status": "valid", "receipt_digest": verification.ReceiptDigest})
}

func finalizeCommand(arguments []string, stdout, stderr io.Writer) int {
	_, planPath, stagePath, verificationPath, observationPath, parseCode := receiptFlags("finalize", arguments, stderr, true, true)
	if parseCode != -1 {
		return parseCode
	}
	plan, stage, verification, err := loadVerificationChain(planPath, stagePath, verificationPath)
	if err != nil {
		fmt.Fprintf(stderr, "finalize media receipt: %v\n", err)
		return exitInvalid
	}
	observation, err := loadColdObservation(observationPath, plan, stage, verification)
	if err != nil {
		fmt.Fprintf(stderr, "finalize media receipt: %v\n", err)
		return exitInvalid
	}
	receipt, err := finalizeReceipts(plan, stage, verification, observation)
	if err != nil {
		fmt.Fprintf(stderr, "finalize media receipt: %v\n", err)
		return exitInvalid
	}
	canonical, err := receipt.CanonicalJSON(plan, stage, verification, observation)
	if err != nil {
		fmt.Fprintf(stderr, "encode final media receipt: %v\n", err)
		return exitInternal
	}
	if _, err := stdout.Write(append(canonical, '\n')); err != nil {
		fmt.Fprintf(stderr, "write final media receipt: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func receiptFlags(name string, arguments []string, stderr io.Writer, requireVerification, requireObservation bool) (*flag.FlagSet, string, string, string, string, int) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	plan := flags.String("plan", "", "absolute canonical plan path")
	stage := flags.String("stage-receipt", "", "absolute canonical stage receipt path")
	verification := flags.String("verification-receipt", "", "absolute canonical verification receipt path")
	observation := flags.String("cold-observation", "", "absolute canonical cold-power observation path")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return flags, "", "", "", "", exitOK
		}
		return flags, "", "", "", "", exitUsage
	}
	if flags.NArg() != 0 || *plan == "" || *stage == "" || requireVerification && *verification == "" || requireObservation && *observation == "" || !requireVerification && *verification != "" || !requireObservation && *observation != "" {
		printUsage(stderr)
		return flags, "", "", "", "", exitUsage
	}
	return flags, *plan, *stage, *verification, *observation, -1
}

func loadVerificationChain(planPath, stagePath, verificationPath string) (mediacontract.Plan, mediacontract.StageReceipt, mediacontract.VerificationReceipt, error) {
	plan, err := loadPlan(planPath)
	if err != nil {
		return mediacontract.Plan{}, mediacontract.StageReceipt{}, mediacontract.VerificationReceipt{}, err
	}
	stage, err := loadStageReceipt(stagePath, plan)
	if err != nil {
		return mediacontract.Plan{}, mediacontract.StageReceipt{}, mediacontract.VerificationReceipt{}, err
	}
	verification, err := loadVerificationReceipt(verificationPath, plan, stage)
	return plan, stage, verification, err
}

func encode(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-media-contract validate-plan --plan ABSOLUTE_PATH")
	fmt.Fprintln(output, "       kaiba-provision-media-contract validate-stage-receipt --plan ABSOLUTE_PATH --stage-receipt ABSOLUTE_PATH")
	fmt.Fprintln(output, "       kaiba-provision-media-contract validate-verification-receipt --plan ABSOLUTE_PATH --stage-receipt ABSOLUTE_PATH --verification-receipt ABSOLUTE_PATH")
	fmt.Fprintln(output, "       kaiba-provision-media-contract finalize --plan ABSOLUTE_PATH --stage-receipt ABSOLUTE_PATH --verification-receipt ABSOLUTE_PATH --cold-observation ABSOLUTE_PATH")
}
