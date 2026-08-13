package provisioning

// RawEvidence is the hardware-neutral boundary value produced by an evidence
// source. Platform packages may embed richer transport provenance alongside
// these bytes in their own acquisition result.
type RawEvidence struct {
	Payload []byte
}

// Adapter normalizes platform evidence into the flat fact vocabulary used by
// device profiles. Platform-specific typed observations may be retained by
// orchestration for richer result output.
type Adapter interface {
	Normalize(RawEvidence) (TargetObservation, error)
}
