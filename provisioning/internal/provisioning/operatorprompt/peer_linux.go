package operatorprompt

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

func systemPeerCredentials(connection *net.UnixConn) (laneguard.OperatorPeer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return laneguard.OperatorPeer{}, fmt.Errorf("access operator socket descriptor: %w", err)
	}
	var (
		credentials *syscall.Ucred
		controlErr  error
	)
	if err := raw.Control(func(descriptor uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return laneguard.OperatorPeer{}, fmt.Errorf("inspect operator peer: %w", err)
	}
	if controlErr != nil {
		return laneguard.OperatorPeer{}, fmt.Errorf("inspect operator peer: %w", controlErr)
	}
	if credentials == nil || credentials.Pid <= 0 {
		return laneguard.OperatorPeer{}, errors.New("operator peer credentials are invalid")
	}
	return laneguard.OperatorPeer{UID: credentials.Uid, GID: credentials.Gid, PID: credentials.Pid}, nil
}
