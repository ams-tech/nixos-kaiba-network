// Package provisioning contains the hardware-neutral contracts used by the
// provisioning probe.
package provisioning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxProfileSize is the largest encoded device profile accepted by the
	// provisioning probe.
	MaxProfileSize = 64 * 1024

	ProfileAPIVersion = "provisioning.kaiba.network/v1alpha1"
	ProfileKind       = "DeviceClassProfile"
)

type ProfileStatus string

const (
	ProfileStatusExperimental ProfileStatus = "experimental"
	ProfileStatusStable       ProfileStatus = "stable"
	ProfileStatusDeprecated   ProfileStatus = "deprecated"
)

type Operator string

const (
	OperatorPresent   Operator = "present"
	OperatorEquals    Operator = "equals"
	OperatorNotEquals Operator = "not_equals"
)

// DeviceProfile is a declarative device-class and unprovisioned-baseline
// policy. Digest is calculated from the exact profile bytes and is never read
// from JSON.
type DeviceProfile struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   ProfileMetadata `json:"metadata"`
	Spec       ProfileSpec     `json:"spec"`
	Digest     string          `json:"-"`
}

type ProfileMetadata struct {
	ID     string        `json:"id"`
	Status ProfileStatus `json:"status"`
}

type ProfileSpec struct {
	Adapter            AdapterRequirement `json:"adapter"`
	RequiredFacts      []string           `json:"requiredFacts"`
	ClassConditions    []Condition        `json:"classConditions"`
	BaselineConditions []Condition        `json:"baselineConditions"`
	DeferredChecks     []DeferredCheck    `json:"deferredChecks"`
}

type AdapterRequirement struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Condition compares a normalized, string-valued observation fact. Value must
// be absent for present and present for equals/not_equals.
type Condition struct {
	ID       string   `json:"id"`
	Fact     string   `json:"fact"`
	Operator Operator `json:"operator"`
	Value    *string  `json:"value,omitempty"`
}

type DeferredCheck struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	factPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$`)
)

// LoadProfile reads and validates one strict JSON device profile.
func LoadProfile(r io.Reader) (DeviceProfile, error) {
	limited := io.LimitReader(r, MaxProfileSize+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("read profile: %w", err)
	}
	return ParseProfile(raw)
}

// ParseProfile validates a profile and records the SHA-256 digest of its exact
// encoded form.
func ParseProfile(raw []byte) (DeviceProfile, error) {
	if len(raw) == 0 {
		return DeviceProfile{}, errors.New("profile is empty")
	}
	if len(raw) > MaxProfileSize {
		return DeviceProfile{}, fmt.Errorf("profile exceeds %d-byte limit", MaxProfileSize)
	}

	generic, err := decodeJSONObject(raw)
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("decode profile: %w", err)
	}
	if err := validateProfileShape(generic); err != nil {
		return DeviceProfile{}, fmt.Errorf("decode profile: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var profile DeviceProfile
	if err := dec.Decode(&profile); err != nil {
		return DeviceProfile{}, fmt.Errorf("decode profile: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return DeviceProfile{}, fmt.Errorf("decode profile: %w", err)
	}
	if err := profile.validate(); err != nil {
		return DeviceProfile{}, fmt.Errorf("validate profile: %w", err)
	}

	digest := sha256.Sum256(raw)
	profile.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return profile, nil
}

func decodeJSONObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodeUniqueValue(dec, "$", nil)
	if err != nil {
		return nil, err
	}
	if err := requireEOF(dec); err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("top-level value must be an object")
	}
	return object, nil
}

func decodeUniqueValue(dec *json.Decoder, path string, first json.Token) (any, error) {
	token := first
	var err error
	if token == nil {
		token, err = dec.Token()
		if err != nil {
			return nil, err
		}
	}

	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}

	switch delim {
	case '{':
		object := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("%s: object key is not a string", path)
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("%s: duplicate key %q", path, key)
			}
			value, err := decodeUniqueValue(dec, path+"."+key, nil)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		var values []any
		for i := 0; dec.More(); i++ {
			value, err := decodeUniqueValue(dec, fmt.Sprintf("%s[%d]", path, i), nil)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return values, nil
	default:
		return nil, fmt.Errorf("%s: unexpected delimiter %q", path, delim)
	}
}

func requireEOF(dec *json.Decoder) error {
	var trailing any
	err := dec.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return fmt.Errorf("trailing data: %w", err)
}

func validateProfileShape(root map[string]any) error {
	if err := exactKeys("$", root, "apiVersion", "kind", "metadata", "spec"); err != nil {
		return err
	}
	metadata, err := objectAt(root, "metadata", "$.metadata")
	if err != nil {
		return err
	}
	if err := exactKeys("$.metadata", metadata, "id", "status"); err != nil {
		return err
	}
	spec, err := objectAt(root, "spec", "$.spec")
	if err != nil {
		return err
	}
	if err := exactKeys("$.spec", spec, "adapter", "requiredFacts", "classConditions", "baselineConditions", "deferredChecks"); err != nil {
		return err
	}
	adapter, err := objectAt(spec, "adapter", "$.spec.adapter")
	if err != nil {
		return err
	}
	if err := exactKeys("$.spec.adapter", adapter, "id", "version"); err != nil {
		return err
	}
	if err := validateObjectArrayShape(spec, "classConditions", []string{"id", "fact", "operator"}, []string{"value"}); err != nil {
		return err
	}
	if err := validateObjectArrayShape(spec, "baselineConditions", []string{"id", "fact", "operator"}, []string{"value"}); err != nil {
		return err
	}
	return validateObjectArrayShape(spec, "deferredChecks", []string{"id", "description"}, nil)
}

func exactKeys(path string, object map[string]any, required ...string) error {
	allowed := make(map[string]struct{}, len(required))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, ok := object[key]; !ok {
			return fmt.Errorf("%s: missing field %q", path, key)
		}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s: unknown field %q", path, key)
		}
	}
	return nil
}

func objectAt(parent map[string]any, key, path string) (map[string]any, error) {
	value, ok := parent[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	return value, nil
}

func validateObjectArrayShape(parent map[string]any, key string, required, optional []string) error {
	path := "$.spec." + key
	values, ok := parent[key].([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", path)
	}
	for i, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d] must be an object", path, i)
		}
		allowed := append(append([]string(nil), required...), optional...)
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, field := range allowed {
			allowedSet[field] = struct{}{}
		}
		for _, field := range required {
			if _, ok := object[field]; !ok {
				return fmt.Errorf("%s[%d]: missing field %q", path, i, field)
			}
		}
		for field := range object {
			if _, ok := allowedSet[field]; !ok {
				return fmt.Errorf("%s[%d]: unknown field %q", path, i, field)
			}
		}
		if key == "classConditions" || key == "baselineConditions" {
			operator, _ := object["operator"].(string)
			_, hasValue := object["value"]
			switch operator {
			case string(OperatorPresent):
				if hasValue {
					return fmt.Errorf("%s[%d]: present condition must omit value", path, i)
				}
			case string(OperatorEquals), string(OperatorNotEquals):
				if !hasValue || object["value"] == nil {
					return fmt.Errorf("%s[%d]: %s condition requires a non-null value", path, i, operator)
				}
			}
		}
	}
	return nil
}

func (p DeviceProfile) validate() error {
	if p.APIVersion != ProfileAPIVersion {
		return fmt.Errorf("apiVersion must be %q", ProfileAPIVersion)
	}
	if p.Kind != ProfileKind {
		return fmt.Errorf("kind must be %q", ProfileKind)
	}
	if !validIdentifier(p.Metadata.ID) {
		return errors.New("metadata.id is invalid")
	}
	switch p.Metadata.Status {
	case ProfileStatusExperimental, ProfileStatusStable, ProfileStatusDeprecated:
	default:
		return fmt.Errorf("metadata.status %q is unsupported", p.Metadata.Status)
	}
	if !validIdentifier(p.Spec.Adapter.ID) {
		return errors.New("spec.adapter.id is invalid")
	}
	if strings.TrimSpace(p.Spec.Adapter.Version) == "" || len(p.Spec.Adapter.Version) > 64 {
		return errors.New("spec.adapter.version is invalid")
	}
	if len(p.Spec.RequiredFacts) == 0 {
		return errors.New("spec.requiredFacts must not be empty")
	}
	if len(p.Spec.ClassConditions) == 0 {
		return errors.New("spec.classConditions must not be empty")
	}
	if len(p.Spec.BaselineConditions) == 0 {
		return errors.New("spec.baselineConditions must not be empty")
	}
	if len(p.Spec.DeferredChecks) == 0 {
		return errors.New("spec.deferredChecks must not be empty")
	}

	requiredFacts := make(map[string]struct{}, len(p.Spec.RequiredFacts))
	for i, fact := range p.Spec.RequiredFacts {
		if !validFact(fact) {
			return fmt.Errorf("spec.requiredFacts[%d] is invalid", i)
		}
		if _, exists := requiredFacts[fact]; exists {
			return fmt.Errorf("spec.requiredFacts contains duplicate %q", fact)
		}
		requiredFacts[fact] = struct{}{}
	}

	conditionIDs := make(map[string]struct{}, len(p.Spec.ClassConditions)+len(p.Spec.BaselineConditions))
	for _, group := range []struct {
		name       string
		conditions []Condition
	}{
		{"classConditions", p.Spec.ClassConditions},
		{"baselineConditions", p.Spec.BaselineConditions},
	} {
		for i, condition := range group.conditions {
			if err := validateCondition(condition); err != nil {
				return fmt.Errorf("spec.%s[%d]: %w", group.name, i, err)
			}
			if _, exists := conditionIDs[condition.ID]; exists {
				return fmt.Errorf("condition id %q is duplicated", condition.ID)
			}
			conditionIDs[condition.ID] = struct{}{}
			if _, required := requiredFacts[condition.Fact]; !required {
				return fmt.Errorf("condition %q references fact %q absent from requiredFacts", condition.ID, condition.Fact)
			}
		}
	}

	deferredIDs := make(map[string]struct{}, len(p.Spec.DeferredChecks))
	for i, check := range p.Spec.DeferredChecks {
		if !validIdentifier(check.ID) {
			return fmt.Errorf("spec.deferredChecks[%d].id is invalid", i)
		}
		if strings.TrimSpace(check.Description) == "" || len(check.Description) > 512 {
			return fmt.Errorf("spec.deferredChecks[%d].description is invalid", i)
		}
		if _, exists := deferredIDs[check.ID]; exists {
			return fmt.Errorf("deferred check id %q is duplicated", check.ID)
		}
		deferredIDs[check.ID] = struct{}{}
	}
	return nil
}

func validateCondition(condition Condition) error {
	if !validIdentifier(condition.ID) {
		return errors.New("id is invalid")
	}
	if !validFact(condition.Fact) {
		return errors.New("fact is invalid")
	}
	switch condition.Operator {
	case OperatorPresent:
		if condition.Value != nil {
			return errors.New("present condition must not have value")
		}
	case OperatorEquals, OperatorNotEquals:
		if condition.Value == nil {
			return fmt.Errorf("%s condition requires value", condition.Operator)
		}
		if len(*condition.Value) > 256 {
			return errors.New("value is too long")
		}
	default:
		return fmt.Errorf("operator %q is unsupported", condition.Operator)
	}
	return nil
}

func validIdentifier(value string) bool {
	return len(value) <= 128 && identifierPattern.MatchString(value)
}

func validFact(value string) bool {
	return len(value) <= 128 && factPattern.MatchString(value)
}

// SortedRequiredFacts returns a defensive, sorted copy suitable for stable
// diagnostics and generated documentation.
func (p DeviceProfile) SortedRequiredFacts() []string {
	facts := append([]string(nil), p.Spec.RequiredFacts...)
	sort.Strings(facts)
	return facts
}
