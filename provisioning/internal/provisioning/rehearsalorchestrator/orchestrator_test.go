package rehearsalorchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/plancompiler"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rehearsal"
)

func TestIntegratedRehearsalUsesRealDurableAuthorityThenOnlySoftwareSimulation(t *testing.T) {
	directory := t.TempDir()
	stores := Stores{
		Control: controlplane.FileStore{Path: filepath.Join(directory, "control.json")},
		Audit:   auditlog.FileStore{Path: filepath.Join(directory, "audit.json")},
	}
	config := Config{RehearsalID: "integrated-happy", Now: testNow()}
	report, err := Run(context.Background(), config, stores)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.ExecutionMode != ExecutionMode || report.AuthorityClass != AuthorityClass ||
		!report.ControlAuditExercised || !report.PersistenceRevalidated ||
		report.HardwareObserved || report.SecurityEnforced || report.MutationEligible {
		t.Fatalf("unsafe report flags = %#v", report)
	}
	if report.Authority.ExecuteRequestCount != 7 || report.Authority.InitialCustomerKeyHash != plancompiler.ZeroCustomerKeyHash ||
		report.Authority.OwnedCustomerKeyHash == report.Authority.InitialCustomerKeyHash {
		t.Fatalf("authority summary = %#v", report.Authority)
	}
	if report.Simulation.Outcome != rehearsal.OutcomeRehearsalPassed || len(report.Simulation.Evidence) != 7 {
		t.Fatalf("simulation outcome/evidence = %q/%d", report.Simulation.Outcome, len(report.Simulation.Evidence))
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenProductionOutcome := "security" + "_applied"
	if strings.Contains(string(encoded), forbiddenProductionOutcome) {
		t.Fatalf("report contains forbidden production outcome: %s", encoded)
	}
	for _, name := range []string{"control.json", "audit.json"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
	}
	if err := RevalidatePersistence(context.Background(), config, Stores{
		Control: controlplane.FileStore{Path: filepath.Join(directory, "control.json")},
		Audit:   auditlog.FileStore{Path: filepath.Join(directory, "audit.json")},
	}, report); err != nil {
		t.Fatalf("explicit second restart validation: %v", err)
	}
}

func TestInjectedSoftwareFailuresRemainNonAuthoritative(t *testing.T) {
	tests := []struct {
		name        string
		disposition rehearsal.StepDisposition
		outcome     rehearsal.Outcome
	}{
		{"failed", rehearsal.StepFailed, rehearsal.OutcomeRehearsalFailed},
		{"uncertain", rehearsal.StepUncertain, rehearsal.OutcomeRehearsalUncertain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := Run(context.Background(), Config{
				RehearsalID: "integrated-" + test.name, Now: testNow(),
				Failure: &rehearsal.FailureInjection{Sequence: 4, Disposition: test.disposition},
			}, Stores{Control: &controlplane.MemoryStore{}, Audit: &auditlog.MemoryStore{}})
			if err != nil {
				t.Fatal(err)
			}
			if report.Simulation.Outcome != test.outcome || len(report.Simulation.Evidence) != 4 ||
				report.HardwareObserved || report.SecurityEnforced || report.MutationEligible {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestRestartValidationRejectsReportAndStoreTampering(t *testing.T) {
	directory := t.TempDir()
	controlPath := filepath.Join(directory, "control.json")
	auditPath := filepath.Join(directory, "audit.json")
	stores := Stores{Control: controlplane.FileStore{Path: controlPath}, Audit: auditlog.FileStore{Path: auditPath}}
	config := Config{RehearsalID: "integrated-tamper", Now: testNow()}
	report, err := Run(context.Background(), config, stores)
	if err != nil {
		t.Fatal(err)
	}

	changed := report
	changed.Authority.PlanDigest = fixtureDigest(config.RehearsalID, "tampered")
	if err := RevalidatePersistence(context.Background(), config, stores, changed); !errors.Is(err, ErrPersistenceMismatch) {
		t.Fatalf("altered report error = %v", err)
	}
	changed = report
	changed.Authority.IntentReceipt = fixtureDigest(config.RehearsalID, "tampered-receipt")
	if err := RevalidatePersistence(context.Background(), config, stores, changed); !errors.Is(err, ErrPersistenceMismatch) {
		t.Fatalf("altered receipt error = %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytesReplaceOnce(t, data, []byte(`"stage": "program_customer_key_and_eeprom"`), []byte(`"stage": "cold_power_cycle"`))
	if err := os.WriteFile(auditPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RevalidatePersistence(context.Background(), config, stores, report); !errors.Is(err, ErrPersistenceMismatch) {
		t.Fatalf("tampered audit error = %v", err)
	}
}

func TestConfigAndCancelledRunFailClosed(t *testing.T) {
	if _, err := Run(context.Background(), Config{}, Stores{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty config error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Run(ctx, Config{RehearsalID: "integrated-cancel", Now: testNow()}, Stores{
		Control: &controlplane.MemoryStore{}, Audit: &auditlog.MemoryStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Simulation.Outcome != rehearsal.OutcomeRehearsalUncertain || report.MutationEligible {
		t.Fatalf("cancelled report = %#v", report)
	}
}

func TestInvalidSimulatorConfigDoesNotCreateAuthorityStores(t *testing.T) {
	directory := t.TempDir()
	controlPath := filepath.Join(directory, "control.json")
	auditPath := filepath.Join(directory, "audit.json")
	_, err := Run(context.Background(), Config{
		RehearsalID: "integrated-invalid-injection", Now: testNow(),
		Failure: &rehearsal.FailureInjection{Sequence: 0, Disposition: rehearsal.StepFailed},
	}, Stores{
		Control: controlplane.FileStore{Path: controlPath},
		Audit:   auditlog.FileStore{Path: auditPath},
	})
	if !errors.Is(err, rehearsal.ErrInvalidFailureInjection) {
		t.Fatalf("invalid injection error = %v", err)
	}
	for _, path := range []string{controlPath, auditPath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("invalid configuration created %s: %v", path, statErr)
		}
	}
}

func TestProductionSourcesHaveNoMutationOrTransportDependencies(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate source directory")
	}
	directory := filepath.Dir(current)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		`"os/exec"`, `"net"`, "physicalrpi5", "laneguard.Guard", "laneguard.NewGuard",
		"RPIBootSysfsPath", "UARTPath", "PowerGPIO", `"/dev/`, `"/sys/`,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if strings.Contains(string(data), value) {
				t.Fatalf("production source %s contains forbidden dependency %q", entry.Name(), value)
			}
		}
	}
}

func bytesReplaceOnce(t *testing.T, data, old, replacement []byte) []byte {
	t.Helper()
	if !strings.Contains(string(data), string(old)) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return []byte(strings.Replace(string(data), string(old), string(replacement), 1))
}

func testNow() time.Time { return time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC) }
