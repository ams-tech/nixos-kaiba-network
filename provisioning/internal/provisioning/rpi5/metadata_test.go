package rpi5

import (
	"fmt"
	"strings"
	"testing"
)

const validMetadata = `{
  "USER_SERIAL_NUM": "A7EB274C",
  "MAC_ADDR": "2C:CF:67:70:76:F3",
  "EEPROM_HASH": "dfc8ef2c77b8152a5cfa008c2296246413fd580fdc26dfacd431e348571a2137",
  "CUSTOMER_KEY_HASH": "0000000000000000000000000000000000000000000000000000000000000000",
  "BOOT_ROM": "0000000A",
  "BOARD_ATTR": "00000000",
  "USER_BOARDREV": "B04170",
  "JTAG_LOCKED": "0",
  "SIGNATURE_MODE": "0",
  "MAC_WIFI_ADDR": "2C:CF:67:70:76:F4",
  "MAC_BT_ADDR": "2C:CF:67:70:76:F5",
  "FACTORY_UUID": "001000911006186073"
}`

func TestParseMetadataNormalizesPi5(t *testing.T) {
	got, err := ParseMetadata([]byte(validMetadata))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if got.AdapterID != AdapterID || got.AdapterVersion != AdapterVersion {
		t.Fatalf("adapter = %s/%s", got.AdapterID, got.AdapterVersion)
	}
	if got.UserSerial != "a7eb274c" || got.FactoryUUID != "001000911006186073" {
		t.Fatalf("identifiers = %q/%q", got.UserSerial, got.FactoryUUID)
	}
	if !got.BoardRevision.NewStyle || got.BoardRevision.Processor != 4 || got.BoardRevision.Model != 0x17 {
		t.Fatalf("decoded revision = %#v", got.BoardRevision)
	}
	if got.BoardRevision.Manufacturer != 0 || got.BoardRevision.PCBRevision != 0 {
		t.Fatalf("decoded zero fields = %#v", got.BoardRevision)
	}
	if got.EthernetMAC != "2c:cf:67:70:76:f3" || got.WiFiMAC != "2c:cf:67:70:76:f4" || got.BluetoothMAC != "2c:cf:67:70:76:f5" {
		t.Fatalf("MAC normalization = %#v", got)
	}
	if got.CustomerKeyState != "unset" || got.VideoCoreJTAGLocked {
		t.Fatalf("security state = %q, locked=%v", got.CustomerKeyState, got.VideoCoreJTAGLocked)
	}
	if len(got.UnknownFields) != 0 || len(got.Extensions) != 0 {
		t.Fatalf("known metadata became extensions: %#v", got.Extensions)
	}
	facts := got.Facts()
	for key, want := range map[string]string{
		"hardware.soc":                      "bcm2712",
		"hardware.board_revision.new_style": "true",
		"hardware.board_revision.processor": "4",
		"hardware.board_revision.model":     "23",
		"security.customer_key_state":       "unset",
		"security.videocore_jtag_locked":    "false",
	} {
		if facts[key] != want {
			t.Errorf("fact %s = %q, want %q", key, facts[key], want)
		}
	}
	if !strings.HasPrefix(got.TargetFingerprint, "sha256:") || !strings.HasPrefix(got.EvidenceDigest, "sha256:") {
		t.Fatalf("digests = %q / %q", got.TargetFingerprint, got.EvidenceDigest)
	}
}

func TestFingerprintUsesOnlyImmutableCorrelationInputs(t *testing.T) {
	first, err := ParseMetadata([]byte(validMetadata))
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(validMetadata, "2C:CF:67:70:76:F3", "2C:CF:67:70:77:F3", 1)
	changed = strings.Replace(changed, "dfc8ef2c77b8152a5cfa008c2296246413fd580fdc26dfacd431e348571a2137", strings.Repeat("1", 64), 1)
	second, err := ParseMetadata([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if first.TargetFingerprint != second.TargetFingerprint {
		t.Fatal("mutable MAC/EEPROM changed target fingerprint")
	}
	if first.EvidenceDigest == second.EvidenceDigest {
		t.Fatal("changed evidence retained evidence digest")
	}
	thirdRaw := strings.Replace(validMetadata, "A7EB274C", "A7EB274D", 1)
	third, err := ParseMetadata([]byte(thirdRaw))
	if err != nil {
		t.Fatal(err)
	}
	if first.TargetFingerprint == third.TargetFingerprint {
		t.Fatal("changed serial retained target fingerprint")
	}
	leadingZeroRaw := strings.Replace(validMetadata, "B04170", "00B04170", 1)
	leadingZero, err := ParseMetadata([]byte(leadingZeroRaw))
	if err != nil {
		t.Fatal(err)
	}
	if leadingZero.BoardRevision.Raw != "00b04170" || leadingZero.TargetFingerprint != first.TargetFingerprint {
		t.Fatal("equivalent revision encoding changed raw preservation or fingerprint")
	}
}

func TestParseMetadataPreservesUnknownAndMakesItDeterministic(t *testing.T) {
	raw := strings.Replace(validMetadata, `"FACTORY_UUID"`, `"Z_FUTURE": "z", "A_FUTURE": "a", "FACTORY_UUID"`, 1)
	got, err := ParseMetadata([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.UnknownFields, ",") != "A_FUTURE,Z_FUTURE" {
		t.Fatalf("unknown = %#v", got.UnknownFields)
	}
	if got.Extensions["A_FUTURE"] != "a" || got.Extensions["Z_FUTURE"] != "z" {
		t.Fatalf("extensions = %#v", got.Extensions)
	}
}

func TestParseMetadataOptionalEEPROMHash(t *testing.T) {
	raw := removeJSONLine(validMetadata, `"EEPROM_HASH"`)
	got, err := ParseMetadata([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.EEPROMHash != "" {
		t.Fatalf("EEPROMHash = %q", got.EEPROMHash)
	}
	if _, exists := got.Facts()["firmware.eeprom_hash"]; exists {
		t.Fatal("optional absent EEPROM hash emitted as a fact")
	}
}

func TestParseMetadataJTAGAndCustomerKeyStates(t *testing.T) {
	lockedRaw := strings.Replace(validMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": "1"`, 1)
	lockedRaw = strings.Replace(lockedRaw, strings.Repeat("0", 64), strings.Repeat("a", 64), 1)
	got, err := ParseMetadata([]byte(lockedRaw))
	if err != nil {
		t.Fatal(err)
	}
	if !got.VideoCoreJTAGLocked || got.CustomerKeyState != "set" {
		t.Fatalf("security state = %#v", got)
	}
}

func TestParseMetadataAcceptsOtherBCM2712ModelsForPolicyRejection(t *testing.T) {
	for _, tt := range []struct{ name, revision, model string }{
		{"cm5", "804180", "24"},
		{"pi500", "8041a0", "26"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(validMetadata, "B04170", tt.revision, 1)
			got, err := ParseMetadata([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if got.Facts()["hardware.board_revision.model"] != tt.model {
				t.Fatalf("facts = %#v", got.Facts())
			}
		})
	}
}

func TestParseMetadataAcceptsPi5MemoryAndPCBVariants(t *testing.T) {
	for _, revision := range []string{"A04170", "B04170", "C04170", "D04170", "B04171"} {
		t.Run(revision, func(t *testing.T) {
			raw := strings.Replace(validMetadata, "B04170", revision, 1)
			got, err := ParseMetadata([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if !got.BoardRevision.NewStyle || got.BoardRevision.Processor != 4 || got.BoardRevision.Model != 0x17 {
				t.Fatalf("decoded revision = %#v", got.BoardRevision)
			}
		})
	}
}

func TestParseMetadataReportsMutationSuccess(t *testing.T) {
	raw := strings.Replace(validMetadata, `"SIGNATURE_MODE": "0"`, `"EEPROM_UPDATE": "success", "SECURE_BOOT_PROVISION": "success", "OTP_BURN": "success", "SIGNATURE_MODE": "0"`, 1)
	got, err := ParseMetadata([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.MutationSuccess, ",") != "EEPROM_UPDATE,OTP_BURN,SECURE_BOOT_PROVISION" {
		t.Fatalf("mutation fields = %#v", got.MutationSuccess)
	}
}

func TestParseMetadataRejectsInvalidInput(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"empty", "", "empty"},
		{"duplicate", strings.Replace(validMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": "0", "JTAG_LOCKED": "1"`, 1), "duplicated"},
		{"nested", strings.Replace(validMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": {"value":"0"}`, 1), "must be a string"},
		{"number", strings.Replace(validMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": 0`, 1), "must be a string"},
		{"trailing", validMetadata + `{}`, "trailing"},
		{"missing serial", removeJSONLine(validMetadata, `"USER_SERIAL_NUM"`), "USER_SERIAL_NUM is required"},
		{"missing Ethernet MAC", removeJSONLine(validMetadata, `"MAC_ADDR"`), "MAC_ADDR is required"},
		{"missing customer key hash", removeJSONLine(validMetadata, `"CUSTOMER_KEY_HASH"`), "CUSTOMER_KEY_HASH is required"},
		{"missing boot ROM", removeJSONLine(validMetadata, `"BOOT_ROM"`), "BOOT_ROM is required"},
		{"missing board attributes", removeJSONLine(validMetadata, `"BOARD_ATTR"`), "BOARD_ATTR is required"},
		{"missing revision", removeJSONLine(validMetadata, `"USER_BOARDREV"`), "USER_BOARDREV is required"},
		{"missing JTAG state", removeJSONLine(validMetadata, `"JTAG_LOCKED"`), "JTAG_LOCKED is required"},
		{"missing factory UUID", removeJSONLine(validMetadata, `"FACTORY_UUID"`), "FACTORY_UUID is required"},
		{"zero serial", strings.Replace(validMetadata, "A7EB274C", "00000000", 1), "must not be zero"},
		{"bad serial", strings.Replace(validMetadata, "A7EB274C", "xyz", 1), "USER_SERIAL_NUM is malformed"},
		{"zero factory UUID", strings.Replace(validMetadata, "001000911006186073", "000000000000000000", 1), "must not be zero"},
		{"punctuated factory UUID", strings.Replace(validMetadata, "001000911006186073", "0010-0091", 1), "FACTORY_UUID is malformed"},
		{"short factory UUID", strings.Replace(validMetadata, "001000911006186073", "x", 1), "FACTORY_UUID is malformed"},
		{"bad revision", strings.Replace(validMetadata, "B04170", "zzzzzz", 1), "USER_BOARDREV is malformed"},
		{"bad hash", strings.Replace(validMetadata, strings.Repeat("0", 64), "abc", 1), "CUSTOMER_KEY_HASH is malformed"},
		{"bad JTAG", strings.Replace(validMetadata, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": "2"`, 1), "must be 0 or 1"},
		{"bad signature mode", strings.Replace(validMetadata, `"SIGNATURE_MODE": "0"`, `"SIGNATURE_MODE": "2"`, 1), "SIGNATURE_MODE must be 0 or 1"},
		{"bad advanced boot", strings.Replace(validMetadata, `"SIGNATURE_MODE": "0"`, `"SIGNATURE_MODE": "0", "ADVANCED_BOOT": "bad"`, 1), "ADVANCED_BOOT is malformed"},
		{"zero MAC", strings.Replace(validMetadata, "2C:CF:67:70:76:F3", "00:00:00:00:00:00", 1), "zero address"},
		{"multicast MAC", strings.Replace(validMetadata, "2C:CF:67:70:76:F3", "01:00:5e:00:00:01", 1), "multicast"},
		{"duplicate MAC", strings.Replace(validMetadata, "2C:CF:67:70:76:F4", "2C:CF:67:70:76:F3", 1), "same MAC address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMetadata([]byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseMetadataLimits(t *testing.T) {
	if _, err := ParseMetadata([]byte(strings.Repeat(" ", MaxMetadataSize+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	var fields []string
	for i := 0; i < MaxMetadataFields+1; i++ {
		fields = append(fields, fmt.Sprintf(`"F%d":"x"`, i))
	}
	if _, err := ParseMetadata([]byte("{" + strings.Join(fields, ",") + "}")); err == nil || !strings.Contains(err.Error(), "fields") {
		t.Fatalf("field limit error = %v", err)
	}
}

func removeJSONLine(raw, marker string) string {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if strings.Contains(line, marker) {
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
	}
	return strings.Replace(strings.Join(lines, "\n"), ",\n}", "\n}", 1)
}
