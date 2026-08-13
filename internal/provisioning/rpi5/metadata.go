// Package rpi5 implements the read-only Raspberry Pi 5 provisioning probe.
//
// The metadata handled by this package is useful for target correlation and
// preflight policy only.  It is not cryptographic device authentication or
// attestation.
package rpi5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kaiba-network/dns-pilot/internal/provisioning"
)

const (
	AdapterID         = "raspberrypi.rpi5.otp-metadata"
	AdapterVersion    = "v1alpha1"
	MaxMetadataSize   = 16 * 1024
	MaxMetadataFields = 64
)

var (
	hex8Pattern        = regexp.MustCompile(`^[0-9a-fA-F]{8}$`)
	hex64Pattern       = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hexRevisionPattern = regexp.MustCompile(`^[0-9a-fA-F]{4,8}$`)
	// rpiboot C40-decodes FACTORY_UUID into groups of three 0-9/A-Z
	// characters. DUID_LENGTH is 36 including the C terminator upstream.
	factoryUUIDPattern = regexp.MustCompile(`^[0-9A-Za-z]{3}(?:[0-9A-Za-z]{3}){0,10}$`)
	macPattern         = regexp.MustCompile(`^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$`)
)

// RawEvidence is metadata together with acquisition provenance. Metadata is
// intentionally retained byte-for-byte so its digest describes the evidence
// that was actually parsed.
type RawEvidence struct {
	Metadata   []byte     `json:"metadata,omitempty"`
	Provenance Provenance `json:"provenance"`
}

// Provenance describes where evidence came from. Live acquisitions populate
// all digest fields; offline callers normally set Source to "offline".
type Provenance struct {
	Source         string `json:"source"`
	LaneID         string `json:"lane_id,omitempty"`
	USBPath        string `json:"usb_path,omitempty"`
	ToolVersion    string `json:"tool_version,omitempty"`
	ToolDigest     string `json:"tool_digest,omitempty"`
	BundleDigest   string `json:"bundle_digest,omitempty"`
	FirmwareDigest string `json:"firmware_digest,omitempty"`
	ConfigDigest   string `json:"config_digest,omitempty"`
}

// Revision is the decoded Raspberry Pi revision code. Values follow the
// documented new-style revision bit allocation.
type Revision struct {
	Raw          string `json:"raw"`
	NewStyle     bool   `json:"new_style"`
	Memory       uint8  `json:"memory_code"`
	Manufacturer uint8  `json:"manufacturer_code"`
	Processor    uint8  `json:"processor_code"`
	Model        uint8  `json:"model_code"`
	PCBRevision  uint8  `json:"pcb_revision"`
}

// Observation is the normalized, typed representation of rpiboot OTP
// metadata. MutationSuccess is evidence that an allegedly read-only live run
// did something unsafe; LiveSource rejects such evidence before returning it.
type Observation struct {
	AdapterID           string            `json:"adapter_id"`
	AdapterVersion      string            `json:"adapter_version"`
	EvidenceDigest      string            `json:"evidence_digest"`
	TargetFingerprint   string            `json:"target_fingerprint"`
	UserSerial          string            `json:"user_serial"`
	FactoryUUID         string            `json:"factory_uuid"`
	BoardRevision       Revision          `json:"board_revision"`
	BoardAttributes     string            `json:"board_attributes"`
	EthernetMAC         string            `json:"ethernet_mac"`
	WiFiMAC             string            `json:"wifi_mac,omitempty"`
	BluetoothMAC        string            `json:"bluetooth_mac,omitempty"`
	BootROM             string            `json:"boot_rom"`
	EEPROMHash          string            `json:"eeprom_hash,omitempty"`
	CustomerKeyHash     string            `json:"customer_key_hash"`
	CustomerKeyState    string            `json:"customer_key_state"`
	VideoCoreJTAGLocked bool              `json:"videocore_jtag_locked"`
	UpstreamFields      map[string]string `json:"upstream_fields,omitempty"`
	Extensions          map[string]string `json:"extensions,omitempty"`
	UnknownFields       []string          `json:"unknown_fields,omitempty"`
	MutationSuccess     []string          `json:"mutation_success_fields,omitempty"`
}

// Adapter implements the hardware-neutral normalization contract.
type Adapter struct{}

// Normalize parses the vendor evidence once and returns policy facts together
// with the typed Pi observation used in the structured result.
func (Adapter) Normalize(evidence provisioning.RawEvidence) (provisioning.TargetObservation, error) {
	observation, err := ParseMetadata(evidence.Payload)
	if err != nil {
		return provisioning.TargetObservation{}, err
	}
	return provisioning.TargetObservation{
		AdapterID:      observation.AdapterID,
		AdapterVersion: observation.AdapterVersion,
		Facts:          observation.Facts(),
		UnknownFields:  append([]string(nil), observation.UnknownFields...),
		Native:         observation,
	}, nil
}

// Facts returns the stable flat fact vocabulary consumed by device profiles.
func (o Observation) Facts() map[string]string {
	soc := "unknown"
	if o.BoardRevision.NewStyle && o.BoardRevision.Processor == 4 {
		soc = "bcm2712"
	}
	facts := map[string]string{
		"hardware.soc":                      soc,
		"hardware.board_revision.new_style": strconv.FormatBool(o.BoardRevision.NewStyle),
		"hardware.board_revision.processor": strconv.FormatUint(uint64(o.BoardRevision.Processor), 10),
		"hardware.board_revision.model":     strconv.FormatUint(uint64(o.BoardRevision.Model), 10),
		"hardware.user_serial":              o.UserSerial,
		"hardware.factory_uuid":             o.FactoryUUID,
		"hardware.board_attributes":         o.BoardAttributes,
		"hardware.ethernet_mac":             o.EthernetMAC,
		"firmware.boot_rom":                 o.BootROM,
		"security.customer_key_hash":        o.CustomerKeyHash,
		"security.customer_key_state":       o.CustomerKeyState,
		"security.videocore_jtag_locked":    strconv.FormatBool(o.VideoCoreJTAGLocked),
	}
	if o.EEPROMHash != "" {
		facts["firmware.eeprom_hash"] = o.EEPROMHash
	}
	return facts
}

var knownFields = map[string]struct{}{
	"USER_SERIAL_NUM": {}, "MAC_ADDR": {}, "EEPROM_HASH": {},
	"CUSTOMER_KEY_HASH": {}, "BOOT_ROM": {}, "BOARD_ATTR": {},
	"USER_BOARDREV": {}, "JTAG_LOCKED": {}, "FACTORY_UUID": {}, "MAC_WIFI_ADDR": {},
	"MAC_BT_ADDR": {}, "EEPROM_UPDATE": {}, "SECURE_BOOT_PROVISION": {},
	"SIGNATURE_MODE": {}, "ADVANCED_BOOT": {},
}

var optionalUpstreamFields = map[string]struct{}{
	"EEPROM_UPDATE": {}, "SECURE_BOOT_PROVISION": {},
	"SIGNATURE_MODE": {}, "ADVANCED_BOOT": {},
}

// ParseMetadata strictly parses and normalizes one rpiboot metadata object.
func ParseMetadata(data []byte) (Observation, error) {
	fields, err := parseStringObject(data, MaxMetadataSize, MaxMetadataFields)
	if err != nil {
		return Observation{}, err
	}

	required := []string{
		"USER_SERIAL_NUM", "MAC_ADDR", "CUSTOMER_KEY_HASH",
		"BOOT_ROM", "BOARD_ATTR", "USER_BOARDREV", "JTAG_LOCKED", "FACTORY_UUID",
	}
	for _, name := range required {
		if fields[name] == "" {
			return Observation{}, fmt.Errorf("metadata field %s is required", name)
		}
	}
	if value := fields["SIGNATURE_MODE"]; value != "" && value != "0" && value != "1" {
		return Observation{}, errors.New("metadata field SIGNATURE_MODE must be 0 or 1")
	}
	if value := fields["ADVANCED_BOOT"]; value != "" && !hex8Pattern.MatchString(value) {
		return Observation{}, errors.New("metadata field ADVANCED_BOOT is malformed")
	}
	for _, name := range []string{"EEPROM_UPDATE", "SECURE_BOOT_PROVISION"} {
		if value := fields[name]; value != "" && !validOperationResult(value) {
			return Observation{}, fmt.Errorf("metadata field %s has an unsupported result", name)
		}
	}

	serial, err := normalizeFixedHex("USER_SERIAL_NUM", fields["USER_SERIAL_NUM"], hex8Pattern)
	if err != nil {
		return Observation{}, err
	}
	if isZeroHex(serial) {
		return Observation{}, errors.New("metadata field USER_SERIAL_NUM must not be zero")
	}
	factoryUUID := strings.ToLower(fields["FACTORY_UUID"])
	if !factoryUUIDPattern.MatchString(factoryUUID) {
		return Observation{}, errors.New("metadata field FACTORY_UUID is malformed")
	}
	if isZeroHex(factoryUUID) {
		return Observation{}, errors.New("metadata field FACTORY_UUID must not be zero")
	}
	revision, err := DecodeRevision(fields["USER_BOARDREV"])
	if err != nil {
		return Observation{}, err
	}
	boardAttr, err := normalizeFixedHex("BOARD_ATTR", fields["BOARD_ATTR"], hex8Pattern)
	if err != nil {
		return Observation{}, err
	}
	bootROM, err := normalizeFixedHex("BOOT_ROM", fields["BOOT_ROM"], hex8Pattern)
	if err != nil {
		return Observation{}, err
	}
	eepromHash := ""
	if fields["EEPROM_HASH"] != "" {
		eepromHash, err = normalizeFixedHex("EEPROM_HASH", fields["EEPROM_HASH"], hex64Pattern)
		if err != nil {
			return Observation{}, err
		}
	}
	keyHash, err := normalizeFixedHex("CUSTOMER_KEY_HASH", fields["CUSTOMER_KEY_HASH"], hex64Pattern)
	if err != nil {
		return Observation{}, err
	}

	ethernet, err := normalizeMAC("MAC_ADDR", fields["MAC_ADDR"])
	if err != nil {
		return Observation{}, err
	}
	wifi, err := normalizeOptionalMAC("MAC_WIFI_ADDR", fields["MAC_WIFI_ADDR"])
	if err != nil {
		return Observation{}, err
	}
	bluetooth, err := normalizeOptionalMAC("MAC_BT_ADDR", fields["MAC_BT_ADDR"])
	if err != nil {
		return Observation{}, err
	}
	macs := map[string]string{}
	for name, value := range map[string]string{"MAC_ADDR": ethernet, "MAC_WIFI_ADDR": wifi, "MAC_BT_ADDR": bluetooth} {
		if value == "" {
			continue
		}
		if previous, exists := macs[value]; exists {
			return Observation{}, fmt.Errorf("metadata fields %s and %s contain the same MAC address", previous, name)
		}
		macs[value] = name
	}

	jtagLocked := false
	switch fields["JTAG_LOCKED"] {
	case "0":
	case "1":
		jtagLocked = true
	default:
		return Observation{}, errors.New("metadata field JTAG_LOCKED must be 0 or 1")
	}

	upstream := make(map[string]string)
	extensions := make(map[string]string)
	unknown := make([]string, 0)
	for name, value := range fields {
		if _, ok := optionalUpstreamFields[name]; ok {
			switch name {
			case "ADVANCED_BOOT":
				upstream[name] = strings.ToLower(value)
			case "EEPROM_UPDATE", "SECURE_BOOT_PROVISION":
				upstream[name] = strings.ToLower(value)
			default:
				upstream[name] = value
			}
			continue
		}
		if _, ok := knownFields[name]; !ok {
			extensions[name] = value
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unknown)

	keyState := "set"
	if isZeroHex(keyHash) {
		keyState = "unset"
	}
	result := Observation{
		AdapterID: AdapterID, AdapterVersion: AdapterVersion,
		EvidenceDigest: digestBytes(data), UserSerial: serial, FactoryUUID: factoryUUID,
		BoardRevision: revision, BoardAttributes: boardAttr,
		EthernetMAC: ethernet, WiFiMAC: wifi, BluetoothMAC: bluetooth,
		BootROM: bootROM, EEPROMHash: eepromHash, CustomerKeyHash: keyHash,
		CustomerKeyState: keyState, VideoCoreJTAGLocked: jtagLocked,
		UpstreamFields: upstream, Extensions: extensions, UnknownFields: unknown,
		MutationSuccess: mutationSuccessFields(fields),
	}
	result.TargetFingerprint = targetFingerprint(factoryUUID, serial, revision.Raw)
	return result, nil
}

func validOperationResult(value string) bool {
	switch strings.ToLower(value) {
	case "success", "failed", "failure", "skipped", "not_requested", "not-run", "disabled":
		return true
	default:
		return false
	}
}

// DecodeRevision decodes Raspberry Pi's documented revision bit field. Old
// style values are returned without fabricated processor or model values.
func DecodeRevision(raw string) (Revision, error) {
	if !hexRevisionPattern.MatchString(raw) {
		return Revision{}, errors.New("metadata field USER_BOARDREV is malformed")
	}
	v, err := strconv.ParseUint(raw, 16, 32)
	if err != nil {
		return Revision{}, errors.New("metadata field USER_BOARDREV is malformed")
	}
	r := Revision{Raw: strings.ToLower(raw), NewStyle: v&(1<<23) != 0}
	if r.NewStyle {
		r.Memory = uint8((v >> 20) & 0x7)
		r.Manufacturer = uint8((v >> 16) & 0xf)
		r.Processor = uint8((v >> 12) & 0xf)
		r.Model = uint8((v >> 4) & 0xff)
		r.PCBRevision = uint8(v & 0xf)
	}
	return r, nil
}

func parseStringObject(data []byte, maxBytes, maxFields int) (map[string]string, error) {
	if len(data) == 0 {
		return nil, errors.New("metadata is empty")
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("metadata exceeds %d bytes", maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("metadata must be one JSON object")
	}
	result := make(map[string]string)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decode metadata key: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("metadata object key is not a string")
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("metadata field %q is duplicated", key)
		}
		if len(result) >= maxFields {
			return nil, fmt.Errorf("metadata exceeds %d fields", maxFields)
		}
		valueToken, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decode metadata field %q: %w", key, err)
		}
		value, ok := valueToken.(string)
		if !ok {
			return nil, fmt.Errorf("metadata field %q must be a string", key)
		}
		result[key] = value
	}
	closing, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	if closing != json.Delim('}') {
		return nil, errors.New("metadata object is not closed")
	}
	if token, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("decode trailing metadata: %w", err)
		}
		return nil, fmt.Errorf("metadata has trailing JSON value %v", token)
	}
	return result, nil
}

func normalizeFixedHex(name, value string, pattern *regexp.Regexp) (string, error) {
	if !pattern.MatchString(value) {
		return "", fmt.Errorf("metadata field %s is malformed", name)
	}
	return strings.ToLower(value), nil
}

func normalizeOptionalMAC(name, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return normalizeMAC(name, value)
}

func normalizeMAC(name, value string) (string, error) {
	if !macPattern.MatchString(value) {
		return "", fmt.Errorf("metadata field %s is malformed", name)
	}
	hw, err := net.ParseMAC(value)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("metadata field %s is malformed", name)
	}
	allZero := true
	for _, b := range hw {
		allZero = allZero && b == 0
	}
	if allZero {
		return "", fmt.Errorf("metadata field %s is the zero address", name)
	}
	if hw[0]&1 != 0 {
		return "", fmt.Errorf("metadata field %s is multicast", name)
	}
	return strings.ToLower(hw.String()), nil
}

func mutationSuccessFields(fields map[string]string) []string {
	var result []string
	for name, value := range fields {
		if !strings.EqualFold(strings.TrimSpace(value), "success") {
			continue
		}
		// This probe has no success-valued result field of its own. Treat every
		// upstream *=success pair as a mutation incident, including future
		// fields whose names this adapter does not yet understand.
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// scanMutationSuccessFields intentionally tolerates duplicate keys and values
// of other JSON types. The strict parser will reject those later, but a valid
// top-level string result ending in "success" must still be surfaced as a
// live safety incident instead of being masked by an unrelated format error.
func scanMutationSuccessFields(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("metadata must be one JSON object")
	}
	var result []string
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("metadata object key is not a string")
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		text, ok := value.(string)
		if ok && strings.EqualFold(strings.TrimSpace(text), "success") {
			result = append(result, key)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	sort.Strings(result)
	return result, nil
}

func isZeroHex(value string) bool {
	for _, r := range value {
		if r != '0' {
			return false
		}
	}
	return value != ""
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func targetFingerprint(factoryUUID, serial, revision string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("kaiba.rpi5.target-fingerprint.v1\x00"))
	value, _ := strconv.ParseUint(revision, 16, 32) // revision was validated by DecodeRevision
	canonicalRevision := strconv.FormatUint(value, 16)
	for _, part := range []string{factoryUUID, serial, canonicalRevision} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
