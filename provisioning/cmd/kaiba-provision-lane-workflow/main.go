package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorworkflow"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitRejected = 3
	maximumJSON  = 1 << 20
)

var clockNow = time.Now

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	var err error
	switch arguments[0] {
	case "prepare-draft":
		err = prepareDraft(ctx, arguments[1:], stdout, stderr)
	case "install-draft":
		err = installDraft(arguments[1:], stdout, stderr)
	case "propose-approval":
		err = proposeApproval(ctx, arguments[1:], stdout, stderr)
	case "apply-approval":
		err = applyApproval(ctx, arguments[1:], stdout, stderr)
	case "propose-next-intent":
		err = proposeNextIntent(ctx, arguments[1:], stdout, stderr)
	case "apply-intent":
		err = applyIntent(ctx, arguments[1:], stdout, stderr)
	case "propose-evidence":
		err = proposeEvidence(ctx, arguments[1:], stdout, stderr)
	case "apply-evidence":
		err = applyEvidence(ctx, arguments[1:], stdout, stderr)
	case "propose-security-applied":
		err = proposeSecurityApplied(ctx, arguments[1:], stdout, stderr)
	case "apply-security-applied":
		err = applySecurityApplied(ctx, arguments[1:], stdout, stderr)
	case "prepare-reconciliation":
		err = prepareReconciliation(ctx, arguments[1:], stdout, stderr)
	case "propose-reconciliation":
		err = proposeReconciliation(ctx, arguments[1:], stdout, stderr)
	case "apply-reconciliation":
		err = applyReconciliation(ctx, arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if errors.Is(err, errUsage) {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "kaiba-provision-lane-workflow: %v\n", err)
	return exitRejected
}

var errUsage = errors.New("invalid command usage")

type controlFlags struct {
	url         string
	certificate string
	privateKey  string
	serverCA    string
}

type pairedFlags struct {
	control  controlFlags
	auditURL string
	auditCA  string
}

func addControlFlags(flags *flag.FlagSet, config *controlFlags) {
	flags.StringVar(&config.url, "control-url", "", "control-service HTTPS origin")
	flags.StringVar(&config.certificate, "tls-cert", "", "role-specific client certificate PEM path")
	flags.StringVar(&config.privateKey, "tls-key", "", "role-specific client private-key PEM path")
	flags.StringVar(&config.serverCA, "control-server-ca", "", "exclusive control-service CA PEM path")
}

func addPairedFlags(flags *flag.FlagSet, config *pairedFlags) {
	addControlFlags(flags, &config.control)
	flags.StringVar(&config.auditURL, "audit-url", "", "independent audit-service HTTPS origin")
	flags.StringVar(&config.auditCA, "audit-server-ca", "", "exclusive audit-service CA PEM path")
}

func (config controlFlags) client() (*operatorworkflow.HTTPControlClient, error) {
	if config.url == "" || !safeCredentialPath(config.certificate) || !safeCredentialPath(config.privateKey) || !safeCredentialPath(config.serverCA) {
		return nil, fmt.Errorf("%w: control URL and absolute non-store TLS credential paths are required", errUsage)
	}
	return operatorworkflow.NewHTTPControlClient(config.url, mtls.ClientFiles{
		Certificate: config.certificate, PrivateKey: config.privateKey, ServerCA: config.serverCA,
	})
}

func (config pairedFlags) clients() (*operatorworkflow.HTTPControlClient, *operatorworkflow.HTTPAuditClient, error) {
	if config.control.url == "" || !safeCredentialPath(config.control.certificate) ||
		!safeCredentialPath(config.control.privateKey) || !safeCredentialPath(config.control.serverCA) ||
		config.auditURL == "" || !safeCredentialPath(config.auditCA) || config.auditCA == config.control.serverCA {
		return nil, nil, fmt.Errorf("%w: distinct authority URLs and absolute non-store TLS credential paths with exclusive server CAs are required", errUsage)
	}
	stationFiles := mtls.ClientFiles{
		Certificate: config.control.certificate, PrivateKey: config.control.privateKey,
		ServerCA: config.control.serverCA,
	}
	auditFiles := stationFiles
	auditFiles.ServerCA = config.auditCA
	// Reuse the bridge's stronger independence check so spelling changes,
	// cross-certification, or duplicate CA keys cannot collapse the two
	// authorities into one trust root.
	if _, _, err := authorityhttp.NewIndependentReaders(config.control.url, stationFiles, config.auditURL, auditFiles); err != nil {
		return nil, nil, err
	}
	control, err := operatorworkflow.NewHTTPControlClient(config.control.url, stationFiles)
	if err != nil {
		return nil, nil, err
	}
	audit, err := operatorworkflow.NewHTTPAuditClient(config.auditURL, auditFiles)
	if err != nil {
		return nil, nil, err
	}
	return control, audit, nil
}

func prepareDraft(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("prepare-draft", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("input", "", "strict reviewed draft-input JSON path")
	outputPath := flags.String("draft-out", "", "new authority-free draft JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *inputPath == "" || *outputPath == "" {
		return fmt.Errorf("%w: prepare-draft requires --input and --draft-out", errUsage)
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		return fmt.Errorf("validate draft output before control changes: %w", err)
	}
	var input operatorworkflow.DraftInput
	if err := loadStrictJSON(*inputPath, &input); err != nil {
		return fmt.Errorf("load reviewed draft input: %w", err)
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	draft, transaction, err := operatorworkflow.PrepareDraft(ctx, input, clockNow().UTC(), client)
	if err != nil {
		return err
	}
	if err := writeCanonicalNew(*outputPath, draft, false); err != nil {
		return fmt.Errorf("publish authority-free draft: %w", err)
	}
	return writeSummary(stdout, map[string]any{
		"status": "draft_prepared", "transaction_id": transaction.ID,
		"resource_version": transaction.ResourceVersion, "fence_epoch": transaction.FenceEpoch,
		"plan_digest": draft.PlanDigest, "draft_path": *outputPath,
	})
}

func installDraft(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("install-draft", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	destination := flags.String("destination", "", "new root-owned lane-guard draft path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" || *destination == "" {
		return fmt.Errorf("%w: install-draft requires --draft and --destination", errUsage)
	}
	var draft laneguard.Plan
	if err := loadStrictJSON(*draftPath, &draft); err != nil {
		return fmt.Errorf("load authority-free draft: %w", err)
	}
	if _, err := plancompiler.DraftFromSnapshot(draft); err != nil {
		return fmt.Errorf("validate authority-free draft: %w", err)
	}
	if err := writeCanonicalNew(*destination, draft, true); err != nil {
		return fmt.Errorf("install immutable draft: %w", err)
	}
	return writeSummary(stdout, map[string]any{
		"status": "draft_installed", "transaction_id": draft.TransactionID,
		"plan_digest": draft.PlanDigest, "destination": *destination,
	})
}

func proposeApproval(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("propose-approval", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	approverID := flags.String("approver-id", "", "independent approver identity")
	outputPath := flags.String("proposal-out", "", "new approval proposal JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" || *approverID == "" || *outputPath == "" {
		return fmt.Errorf("%w: propose-approval requires --draft, --approver-id, and --proposal-out", errUsage)
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		return err
	}
	draft, err := loadDraft(*draftPath)
	if err != nil {
		return err
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	transaction, err := client.GetTransaction(ctx, draft.TransactionID)
	if err != nil {
		return err
	}
	proposal, err := operatorworkflow.NewApprovalProposal(draft, transaction, *approverID, clockNow().UTC())
	if err != nil {
		return err
	}
	if err := writeCanonicalNew(*outputPath, proposal, false); err != nil {
		return err
	}
	return writeSummary(stdout, map[string]any{
		"status": "approval_proposed", "approval_id": proposal.ApprovalID,
		"plan_digest": draft.PlanDigest, "proposal_path": *outputPath,
	})
}

func applyApproval(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply-approval", flag.ContinueOnError)
	flags.SetOutput(stderr)
	proposalPath := flags.String("proposal", "", "reviewed approval proposal JSON path")
	var network pairedFlags
	addPairedFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *proposalPath == "" {
		return fmt.Errorf("%w: apply-approval requires --proposal", errUsage)
	}
	var proposal operatorworkflow.ApprovalProposal
	if err := loadStrictJSON(*proposalPath, &proposal); err != nil {
		return err
	}
	control, audit, err := network.clients()
	if err != nil {
		return err
	}
	transaction, err := operatorworkflow.ApplyApproval(ctx, proposal, control, audit, control)
	if err != nil {
		return err
	}
	return writeSummary(stdout, transactionSummary("approval_recorded", transaction))
}

func proposeNextIntent(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("propose-next-intent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	outputPath := flags.String("proposal-out", "", "new next-operation intent proposal JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" || *outputPath == "" {
		return fmt.Errorf("%w: propose-next-intent requires --draft and --proposal-out", errUsage)
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		return err
	}
	draft, err := loadDraft(*draftPath)
	if err != nil {
		return err
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	proposal, _, err := operatorworkflow.PrepareNextIntent(ctx, draft, clockNow().UTC(), client)
	if err != nil {
		return err
	}
	if err := writeCanonicalNew(*outputPath, proposal, false); err != nil {
		return err
	}
	operation := draft.Operations[proposal.Sequence-1]
	return writeSummary(stdout, map[string]any{
		"status": "intent_proposed", "sequence": proposal.Sequence,
		"operation": operation.Operation, "required_boot_mode": operation.RequiredBootMode,
		"proposal_path": *outputPath,
	})
}

func applyIntent(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply-intent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	proposalPath := flags.String("proposal", "", "reviewed next-operation intent proposal JSON path")
	var network pairedFlags
	addPairedFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *proposalPath == "" {
		return fmt.Errorf("%w: apply-intent requires --proposal", errUsage)
	}
	var proposal operatorworkflow.IntentProposal
	if err := loadStrictJSON(*proposalPath, &proposal); err != nil {
		return err
	}
	control, audit, err := network.clients()
	if err != nil {
		return err
	}
	transaction, err := operatorworkflow.ApplyIntent(ctx, proposal, control, audit, control)
	if err != nil {
		return err
	}
	return writeSummary(stdout, transactionSummary("intent_recorded", transaction))
}

func proposeEvidence(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("propose-evidence", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	attemptPath := flags.String("attempt", "", "lane-guard attempt JSON path")
	outputPath := flags.String("proposal-out", "", "new attempt-evidence proposal JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" || *attemptPath == "" || *outputPath == "" {
		return fmt.Errorf("%w: propose-evidence requires --draft, --attempt, and --proposal-out", errUsage)
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		return err
	}
	draft, err := loadDraft(*draftPath)
	if err != nil {
		return err
	}
	var attempt laneguard.Attempt
	if err := loadTrustedStrictJSON(*attemptPath, &attempt); err != nil {
		return fmt.Errorf("load lane-guard attempt: %w", err)
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	transaction, err := client.GetTransaction(ctx, draft.TransactionID)
	if err != nil {
		return err
	}
	proposal, err := operatorworkflow.NewEvidenceProposal(draft, transaction, attempt, clockNow().UTC())
	if err != nil {
		return err
	}
	if err := writeCanonicalNew(*outputPath, proposal, false); err != nil {
		return err
	}
	return writeSummary(stdout, map[string]any{
		"status": "evidence_proposed", "sequence": attempt.Sequence,
		"attempt_status": attempt.Status, "proposal_path": *outputPath,
	})
}

func applyEvidence(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply-evidence", flag.ContinueOnError)
	flags.SetOutput(stderr)
	proposalPath := flags.String("proposal", "", "reviewed attempt-evidence proposal JSON path")
	var network pairedFlags
	addPairedFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *proposalPath == "" {
		return fmt.Errorf("%w: apply-evidence requires --proposal", errUsage)
	}
	var proposal operatorworkflow.EvidenceProposal
	if err := loadStrictJSON(*proposalPath, &proposal); err != nil {
		return err
	}
	control, audit, err := network.clients()
	if err != nil {
		return err
	}
	transaction, err := operatorworkflow.ApplyEvidence(ctx, proposal, control, audit, control)
	if err != nil {
		return err
	}
	return writeSummary(stdout, transactionSummary("evidence_recorded", transaction))
}

func proposeSecurityApplied(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("propose-security-applied", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	outputPath := flags.String("proposal-out", "", "new security-applied proposal JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" || *outputPath == "" {
		return fmt.Errorf("%w: propose-security-applied requires --draft and --proposal-out", errUsage)
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		return err
	}
	draft, err := loadDraft(*draftPath)
	if err != nil {
		return err
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	transaction, err := client.GetTransaction(ctx, draft.TransactionID)
	if err != nil {
		return err
	}
	proposal, err := operatorworkflow.NewSecurityAppliedProposal(draft, transaction, clockNow().UTC())
	if err != nil {
		return err
	}
	if err := writeCanonicalNew(*outputPath, proposal, false); err != nil {
		return err
	}
	return writeSummary(stdout, map[string]any{
		"status": "security_applied_proposed", "evidence_digest": proposal.EvidenceDigest,
		"rollback_status": proposal.RollbackStatus, "release_classification": proposal.ReleaseClassification,
		"proposal_path": *outputPath,
	})
}

func applySecurityApplied(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply-security-applied", flag.ContinueOnError)
	flags.SetOutput(stderr)
	proposalPath := flags.String("proposal", "", "reviewed security-applied proposal JSON path")
	var network pairedFlags
	addPairedFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *proposalPath == "" {
		return fmt.Errorf("%w: apply-security-applied requires --proposal", errUsage)
	}
	var proposal operatorworkflow.SecurityAppliedProposal
	if err := loadStrictJSON(*proposalPath, &proposal); err != nil {
		return err
	}
	control, audit, err := network.clients()
	if err != nil {
		return err
	}
	transaction, err := operatorworkflow.ApplySecurityApplied(ctx, proposal, control, audit, control)
	if err != nil {
		return err
	}
	result := transactionSummary("security_applied_recorded", transaction)
	if transaction.SecurityApplied != nil {
		result["evidence_digest"] = transaction.SecurityApplied.EvidenceDigest
		result["rollback_status"] = transaction.SecurityApplied.RollbackStatus
		result["release_classification"] = transaction.SecurityApplied.ReleaseClassification
	}
	return writeSummary(stdout, result)
}

func prepareReconciliation(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("prepare-reconciliation", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" {
		return fmt.Errorf("%w: prepare-reconciliation requires --draft", errUsage)
	}
	draft, err := loadDraft(*draftPath)
	if err != nil {
		return err
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	transaction, err := operatorworkflow.PrepareReconciliationClaim(ctx, draft, clockNow().UTC(), client)
	if err != nil {
		return err
	}
	result := transactionSummary("reconciliation_claim_prepared", transaction)
	result["claim_id"] = transaction.ActiveClaim.ID
	result["claim_mode"] = transaction.ActiveClaim.Mode
	result["claim_expires_at"] = transaction.ActiveClaim.ExpiresAt
	return writeSummary(stdout, result)
}

func proposeReconciliation(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("propose-reconciliation", flag.ContinueOnError)
	flags.SetOutput(stderr)
	draftPath := flags.String("draft", "", "reviewed authority-free draft JSON path")
	attemptPath := flags.String("attempt", "", "trusted lane-guard reconciliation-attempt JSON path")
	outputPath := flags.String("proposal-out", "", "new reconciliation proposal JSON path")
	var network controlFlags
	addControlFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *draftPath == "" || *attemptPath == "" || *outputPath == "" {
		return fmt.Errorf("%w: propose-reconciliation requires --draft, --attempt, and --proposal-out", errUsage)
	}
	if err := evidencefile.ValidateNewPath(*outputPath); err != nil {
		return err
	}
	draft, err := loadDraft(*draftPath)
	if err != nil {
		return err
	}
	var attempt laneguard.Attempt
	if err := loadTrustedStrictJSON(*attemptPath, &attempt); err != nil {
		return fmt.Errorf("load trusted reconciliation attempt: %w", err)
	}
	client, err := network.client()
	if err != nil {
		return err
	}
	transaction, err := client.GetTransaction(ctx, draft.TransactionID)
	if err != nil {
		return err
	}
	proposal, err := operatorworkflow.NewReconciliationProposal(draft, transaction, attempt, clockNow().UTC())
	if err != nil {
		return err
	}
	if err := writeCanonicalNew(*outputPath, proposal, false); err != nil {
		return err
	}
	return writeSummary(stdout, map[string]any{
		"status": "reconciliation_proposed", "sequence": attempt.Sequence,
		"resolution": proposal.Resolution, "proposal_path": *outputPath,
	})
}

func applyReconciliation(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply-reconciliation", flag.ContinueOnError)
	flags.SetOutput(stderr)
	proposalPath := flags.String("proposal", "", "reviewed reconciliation proposal JSON path")
	var network pairedFlags
	addPairedFlags(flags, &network)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *proposalPath == "" {
		return fmt.Errorf("%w: apply-reconciliation requires --proposal", errUsage)
	}
	var proposal operatorworkflow.ReconciliationProposal
	if err := loadStrictJSON(*proposalPath, &proposal); err != nil {
		return err
	}
	control, audit, err := network.clients()
	if err != nil {
		return err
	}
	transaction, err := operatorworkflow.ApplyReconciliation(ctx, proposal, control, audit, control)
	if err != nil {
		return err
	}
	return writeSummary(stdout, transactionSummary("reconciliation_recorded", transaction))
}

func loadDraft(path string) (laneguard.Plan, error) {
	var draft laneguard.Plan
	if err := loadStrictJSON(path, &draft); err != nil {
		return laneguard.Plan{}, fmt.Errorf("load authority-free draft: %w", err)
	}
	if _, err := plancompiler.DraftFromSnapshot(draft); err != nil {
		return laneguard.Plan{}, fmt.Errorf("validate authority-free draft: %w", err)
	}
	return draft, nil
}

func loadStrictJSON(path string, target any) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("JSON input path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumJSON {
		return errors.New("JSON input must be a nonempty regular non-symlink file no larger than 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumJSON+1))
	if err != nil {
		return err
	}
	if len(data) > maximumJSON {
		return errors.New("JSON input exceeds 1 MiB")
	}
	return controlplane.DecodeStrict(data, target)
}

// Lane-attempt evidence is an authority input, not merely a review artifact.
// Only the root-owned immutable publication boundary used by the lane guard is
// accepted; a caller-owned JSON file must never be promoted into control/audit
// evidence merely because its fields are internally consistent.
func loadTrustedStrictJSON(path string, target any) error {
	data, err := evidencefile.ReadTrustedExisting(path, maximumJSON)
	if err != nil {
		return err
	}
	return controlplane.DecodeStrict(data, target)
}

func writeCanonicalNew(path string, value any, trusted bool) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if trusted {
		return evidencefile.WriteCanonicalNewTrusted(path, encoded)
	}
	return evidencefile.WriteCanonicalNew(path, encoded)
}

func writeSummary(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func transactionSummary(status string, transaction controlplane.Transaction) map[string]any {
	result := map[string]any{
		"status": status, "transaction_id": transaction.ID,
		"transaction_status": transaction.Status, "resource_version": transaction.ResourceVersion,
		"fence_epoch": transaction.FenceEpoch,
	}
	if len(transaction.Operations) != 0 {
		last := transaction.Operations[len(transaction.Operations)-1]
		result["operation_id"] = last.ID
		result["operation"] = last.Operation
		result["operation_status"] = last.Status
	}
	return result
}

func safeCredentialPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/nix/store" &&
		!strings.HasPrefix(path, "/nix/store/")
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-provision-lane-workflow prepare-draft --input FILE --draft-out FILE --control-url HTTPS_ORIGIN --tls-cert FILE --tls-key FILE --control-server-ca FILE")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow install-draft --draft FILE --destination FILE")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow propose-approval --draft FILE --approver-id ID --proposal-out FILE [station control TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow apply-approval --proposal FILE [approver control/audit TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow propose-next-intent --draft FILE --proposal-out FILE [station control TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow apply-intent --proposal FILE [station control/audit TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow propose-evidence --draft FILE --attempt FILE --proposal-out FILE [station control TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow apply-evidence --proposal FILE [station control/audit TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow propose-security-applied --draft FILE --proposal-out FILE [station control TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow apply-security-applied --proposal FILE [station control/audit TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow prepare-reconciliation --draft FILE [station control TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow propose-reconciliation --draft FILE --attempt FILE --proposal-out FILE [station control TLS flags]")
	fmt.Fprintln(output, "       kaiba-provision-lane-workflow apply-reconciliation --proposal FILE [station control/audit TLS flags]")
}
