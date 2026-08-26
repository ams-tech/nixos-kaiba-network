package operatorworkflow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

func TestApprovalWorkflowAcrossIndependentMutualTLSAuthorities(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	clientCA := newApprovalMTLSCA(t, "approval-client-ca", now, 1)
	controlServerCA := newApprovalMTLSCA(t, "approval-control-server-ca", now, 2)
	auditServerCA := newApprovalMTLSCA(t, "approval-audit-server-ca", now, 3)
	if reflect.DeepEqual(controlServerCA.der, auditServerCA.der) {
		t.Fatal("control and audit unexpectedly share a server CA")
	}

	stationCertificate := clientCA.issue(t, "station-client", now, 4, false,
		"spiffe://kaiba.network/station/station-1/lane/lane-1")
	approverCertificate := clientCA.issue(t, "approver-client", now, 5, false,
		"spiffe://kaiba.network/approver/approver-1")
	controlCertificate := controlServerCA.issue(t, "control-server", now, 6, true, "")
	auditCertificate := auditServerCA.issue(t, "audit-server", now, 7, true, "")

	clientCAPath := writeApprovalMTLSCertificate(t, directory, "client-ca.crt", clientCA.der)
	controlServerCAPath := writeApprovalMTLSCertificate(t, directory, "control-server-ca.crt", controlServerCA.der)
	auditServerCAPath := writeApprovalMTLSCertificate(t, directory, "audit-server-ca.crt", auditServerCA.der)
	stationCertificatePath := writeApprovalMTLSCertificate(t, directory, "station.crt", stationCertificate.der)
	stationKeyPath := writeApprovalMTLSKey(t, directory, "station.key", stationCertificate.key)
	approverCertificatePath := writeApprovalMTLSCertificate(t, directory, "approver.crt", approverCertificate.der)
	approverKeyPath := writeApprovalMTLSKey(t, directory, "approver.key", approverCertificate.key)

	controlStore := &controlplane.MemoryStore{}
	auditStore := &auditlog.MemoryStore{}
	controlService, err := controlplane.NewService(
		controlStore,
		controlplane.WithClock(func() time.Time { return now }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) { return prefix + "-approval-mtls", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := auditlog.NewService(
		auditStore,
		auditlog.WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}

	controlServer := startApprovalMTLSServer(t, directory, "control", controlCertificate, clientCAPath,
		controlplane.Handler(controlService, mtls.MutualTLSIdentityPolicy()))
	auditServer := startApprovalMTLSServer(t, directory, "audit", auditCertificate, clientCAPath,
		auditlog.Handler(auditService, mtls.MutualTLSIdentityPolicy()))

	stationControlFiles := mtls.ClientFiles{
		Certificate: stationCertificatePath,
		PrivateKey:  stationKeyPath,
		ServerCA:    controlServerCAPath,
	}
	stationControl, err := NewHTTPControlClient(controlServer.URL, stationControlFiles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stationControl.client.CloseIdleConnections)

	input := approvalMTLSDraftInput(now)
	snapshot, targetBound, err := PrepareDraft(t.Context(), input, now, stationControl)
	if err != nil {
		t.Fatalf("station prepare draft over mutual TLS: %v", err)
	}
	stationRead, err := stationControl.GetTransaction(t.Context(), input.TransactionID)
	if err != nil {
		t.Fatalf("station read target-bound transaction over mutual TLS: %v", err)
	}
	if !reflect.DeepEqual(stationRead, targetBound) {
		t.Fatalf("station transaction read differs from preparation result\nread: %#v\nprepared: %#v", stationRead, targetBound)
	}
	proposal, err := NewApprovalProposal(snapshot, stationRead, "approver-1", now)
	if err != nil {
		t.Fatalf("station prepare approval proposal: %v", err)
	}

	_, stationRecordRequest, err := proposal.requests(validPlaceholderDigest)
	if err != nil {
		t.Fatal(err)
	}
	stationPreflightRequest := approvalPreflightRequest(proposal, stationRecordRequest)
	if _, err := stationControl.PreflightApproval(t.Context(), stationPreflightRequest); err == nil {
		t.Fatal("station certificate authorized approval preflight")
	}
	if _, err := stationControl.RecordApproval(t.Context(), stationRecordRequest); err == nil {
		t.Fatal("station certificate authorized approval record")
	}
	if records := auditService.Records(input.TransactionID); len(records) != 0 {
		t.Fatalf("denied station approval created %d audit records", len(records))
	}
	unchanged, err := controlService.GetTransaction(context.Background(), input.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.ResourceVersion != targetBound.ResourceVersion || unchanged.Status != controlplane.StatusTargetBound || unchanged.Approval != nil {
		t.Fatalf("denied station approval mutated control state: %#v", unchanged)
	}

	approverControlFiles := mtls.ClientFiles{
		Certificate: approverCertificatePath,
		PrivateKey:  approverKeyPath,
		ServerCA:    controlServerCAPath,
	}
	approverAuditFiles := mtls.ClientFiles{
		Certificate: approverCertificatePath,
		PrivateKey:  approverKeyPath,
		ServerCA:    auditServerCAPath,
	}
	if approverControlFiles.PrivateKey == stationKeyPath || approverAuditFiles.PrivateKey == stationKeyPath {
		t.Fatal("approver client construction includes the station private key")
	}
	approverControl, err := NewHTTPControlClient(controlServer.URL, approverControlFiles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(approverControl.client.CloseIdleConnections)
	approverAudit, err := NewHTTPAuditClient(auditServer.URL, approverAuditFiles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(approverAudit.client.CloseIdleConnections)
	assertApprovalMTLSApproverCredential(t, "control", approverControl.client, stationCertificate, approverCertificate)
	assertApprovalMTLSApproverCredential(t, "audit", approverAudit.client, stationCertificate, approverCertificate)

	if _, err := approverControl.GetTransaction(t.Context(), input.TransactionID); err == nil {
		t.Fatal("approver certificate authorized station transaction GET")
	}
	approved, err := ApplyApproval(t.Context(), proposal, approverControl, approverAudit, approverControl)
	if err != nil {
		t.Fatalf("approver apply approval over independent mutual TLS authorities: %v", err)
	}
	if approved.Status != controlplane.StatusCommitApproved || approved.Approval == nil {
		t.Fatalf("approval result = %#v", approved)
	}

	durableControl, err := controlplane.NewService(
		controlStore,
		controlplane.WithClock(func() time.Time { return now }),
		controlplane.WithIDGenerator(func(prefix string) (string, error) { return prefix + "-approval-mtls", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	durableAudit, err := auditlog.NewService(auditStore, auditlog.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := durableControl.GetTransaction(context.Background(), input.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	records := durableAudit.Records(input.TransactionID)
	if len(records) != 1 {
		t.Fatalf("durable approval audit records = %d, want 1", len(records))
	}
	record := records[0]
	wantReceiptID := approvalMTLSReceiptID(record.EventHash)
	if durable.Status != controlplane.StatusCommitApproved || durable.Approval == nil ||
		durable.Approval.ID != proposal.ApprovalID || durable.Approval.ApproverID != proposal.ApproverID ||
		durable.Approval.TransactionDigest != proposal.TransactionDigest ||
		durable.Approval.PlanDigest != snapshot.PlanDigest ||
		durable.Approval.StationID != snapshot.StationID || durable.Approval.LaneID != snapshot.LaneID ||
		durable.Approval.FenceEpoch != snapshot.FenceEpoch ||
		durable.Approval.TargetFingerprint != snapshot.TargetFingerprint ||
		durable.Approval.Release != snapshot.Release ||
		durable.Approval.AuditReceiptID != wantReceiptID ||
		!reflect.DeepEqual(durable.Approval.AllowedOperations, stationPreflightRequest.AllowedOperations) {
		t.Fatalf("durable control approval does not bind proposal and audit receipt: %#v", durable.Approval)
	}
	if record.Event.EventID != proposal.ApprovalID || record.Event.TransactionID != snapshot.TransactionID ||
		record.Event.Stage != "plan_approval" || record.Event.InputDigest != snapshot.PlanDigest ||
		record.Event.StationID != snapshot.StationID || record.Event.LaneID != snapshot.LaneID ||
		record.Event.FenceEpoch != snapshot.FenceEpoch || len(record.Event.Actors) != 1 ||
		record.Event.Actors[0] != (auditlog.Actor{ID: proposal.ApproverID, Role: "approver"}) {
		t.Fatalf("durable approval audit event does not bind proposal: %#v", record.Event)
	}
}

func assertApprovalMTLSApproverCredential(t *testing.T, authority string, client *http.Client, station, approver approvalMTLSCertificate) {
	t.Helper()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("%s approver client has an unexpected TLS transport", authority)
	}
	loaded := transport.TLSClientConfig.Certificates[0]
	if len(loaded.Certificate) == 0 || !bytes.Equal(loaded.Certificate[0], approver.der) || bytes.Equal(loaded.Certificate[0], station.der) {
		t.Fatalf("%s approver client loaded the wrong certificate", authority)
	}
	loadedKey, ok := loaded.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || loadedKey.D.Cmp(approver.key.D) != 0 || loadedKey.D.Cmp(station.key.D) == 0 {
		t.Fatalf("%s approver client loaded the wrong private key", authority)
	}
}

func approvalMTLSDraftInput(now time.Time) DraftInput {
	return DraftInput{
		SchemaVersion: DraftInputSchemaVersion,
		StationID:     "station-1", LaneID: "lane-1", TransactionID: "transaction-mtls-approval",
		AssetID: "asset-mtls-approval", IntendedLogicalID: "kaiba-mtls-approval", ProfileID: "rpi5-test",
		PolicyDigest: approvalMTLSDigest("1"),
		Release: releasebinding.Binding{
			SignedReleaseManifestDigest: approvalMTLSDigest("2"),
			LaneGuardPackageDigest:      approvalMTLSDigest("3"),
			CompiledArtifactSetDigest:   approvalMTLSDigest("4"),
			ExpectedCustomerKeyHash:     approvalMTLSDigest("5"),
			ExpectedEEPROMDigest:        approvalMTLSDigest("6"),
			ExpectedBootImageDigest:     approvalMTLSDigest("7"),
		},
		TargetFingerprint: approvalMTLSDigest("8"), ObservationDigest: approvalMTLSDigest("9"),
		InitialState: laneguard.DirectState{
			CustomerKeyHash: controlplane.UnownedCustomerKeyHash,
			EEPROMHash:      approvalMTLSDigest("a"),
			SecurityState:   "fresh",
			PowerState:      "powered_off",
		},
		ApprovalExpiresAt: now.Add(30 * time.Minute),
		AuthorizationIDs: []string{
			"authorization-mtls-1", "authorization-mtls-2", "authorization-mtls-3", "authorization-mtls-4",
			"authorization-mtls-5", "authorization-mtls-6", "authorization-mtls-7",
		},
		MaximumSeconds: []uint32{60, 90, 60, 120, 60, 120, 120},
	}
}

type approvalMTLSCA struct {
	certificate *x509.Certificate
	der         []byte
	key         *ecdsa.PrivateKey
}

type approvalMTLSCertificate struct {
	der []byte
	key *ecdsa.PrivateKey
}

func newApprovalMTLSCA(t *testing.T, commonName string, now time.Time, serial int64) approvalMTLSCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return approvalMTLSCA{certificate: certificate, der: der, key: key}
}

func (ca approvalMTLSCA) issue(t *testing.T, commonName string, now time.Time, serial int64, server bool, identity string) approvalMTLSCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		identityURI, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{identityURI}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return approvalMTLSCertificate{der: der, key: key}
}

func startApprovalMTLSServer(t *testing.T, directory, name string, certificate approvalMTLSCertificate, clientCAPath string, handler http.Handler) *httptest.Server {
	t.Helper()
	serverTLS, err := mtls.LoadServerConfig(mtls.Files{
		Certificate: writeApprovalMTLSCertificate(t, directory, name+".crt", certificate.der),
		PrivateKey:  writeApprovalMTLSKey(t, directory, name+".key", certificate.key),
		ClientCA:    clientCAPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func writeApprovalMTLSCertificate(t *testing.T, directory, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeApprovalMTLSKey(t *testing.T, directory, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func approvalMTLSDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func approvalMTLSReceiptID(eventHash string) string {
	digest := sha256.Sum256([]byte("kaiba-audit-receipt\x00" + eventHash))
	return "sha256:" + hex.EncodeToString(digest[:])
}
