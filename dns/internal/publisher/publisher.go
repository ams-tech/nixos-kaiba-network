package publisher

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/dnswriter"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
)

// Leadership is an explicit replacement seam for a future distributed lease.
// The pilot deploys exactly one publisher and therefore uses StaticLeadership.
type Leadership interface {
	Acquire(context.Context) (release func(), acquired bool, err error)
}

type StaticLeadership struct{}

func (StaticLeadership) Acquire(context.Context) (func(), bool, error) {
	return func() {}, true, nil
}

// Publisher is the application boundary used by one-shot tests and the daemon.
type Publisher interface {
	RunOnce(context.Context) error
}

type Service struct {
	Store      store.DesiredState
	DNS        dnswriter.Writer
	Observer   dnswriter.Observer
	Leadership Leadership
	TTL        uint32
	BatchSize  int
	Now        func() time.Time
	OnError    func(error)
}

func (s *Service) validate() error {
	if s.Store == nil || s.DNS == nil {
		return errors.New("desired-state store and DNS writer are required")
	}
	if s.TTL == 0 {
		return errors.New("DNS TTL must be positive")
	}
	if s.Leadership == nil {
		s.Leadership = StaticLeadership{}
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.BatchSize <= 0 {
		s.BatchSize = 100
	}
	return nil
}

func (s *Service) RunOnce(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	release, acquired, err := s.Leadership.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire publication leadership: %w", err)
	}
	if !acquired {
		return nil
	}
	defer release()
	var failures []error
	if _, err := s.Store.ExpireLeases(ctx, s.Now().UTC()); err != nil {
		failures = append(failures, fmt.Errorf("expire leases: %w", err))
	}
	pending, err := s.Store.ListOriginPending(ctx, s.BatchSize)
	if err != nil {
		failures = append(failures, fmt.Errorf("list origin-pending records: %w", err))
	} else {
		for _, intent := range pending {
			if err := s.DNS.ReplaceAddressRRsets(ctx, intent.Hostname, cloneAddresses(intent.Addresses), s.TTL); err != nil {
				wrapped := fmt.Errorf("publish %s generation %d: %w", intent.DeviceID, intent.Generation, err)
				failures = append(failures, wrapped)
				_ = s.Store.MarkPublicationError(ctx, intent.DeviceID, intent.Generation, err.Error())
				continue
			}
			if err := s.Store.MarkOriginApplied(ctx, intent.DeviceID, intent.Generation); err != nil {
				failures = append(failures, fmt.Errorf("mark %s generation %d applied: %w", intent.DeviceID, intent.Generation, err))
			}
		}
	}
	if s.Observer != nil {
		pending, err := s.Store.ListObservationPending(ctx, s.BatchSize)
		if err != nil {
			failures = append(failures, fmt.Errorf("list observation-pending records: %w", err))
		} else {
			for _, intent := range pending {
				observed, err := s.Observer.ObserveAddressRRsets(ctx, intent.Hostname, cloneAddresses(intent.Addresses))
				if err != nil {
					failures = append(failures, fmt.Errorf("observe %s generation %d: %w", intent.DeviceID, intent.Generation, err))
					continue
				}
				if observed {
					if err := s.Store.MarkPubliclyObserved(ctx, intent.DeviceID, intent.Generation); err != nil {
						failures = append(failures, fmt.Errorf("mark %s generation %d observed: %w", intent.DeviceID, intent.Generation, err))
					}
				}
			}
		}
	}
	return errors.Join(failures...)
}

func (s *Service) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("poll interval must be positive")
	}
	if err := s.validate(); err != nil {
		return err
	}
	run := func() {
		if err := s.RunOnce(ctx); err != nil && s.OnError != nil {
			s.OnError(err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			run()
		}
	}
}

func cloneAddresses(addresses []netip.Addr) []netip.Addr {
	return append([]netip.Addr(nil), addresses...)
}
