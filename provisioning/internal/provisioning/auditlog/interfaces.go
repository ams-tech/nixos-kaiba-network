package auditlog

import "context"

// Appender is the narrow append-only capability granted to stations and other
// control services. It intentionally exposes no mutation or deletion method.
type Appender interface {
	Append(context.Context, AppendRequest) (Receipt, error)
}
