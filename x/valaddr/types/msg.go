package types

import (
	"net"
	"strconv"
	"strings"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// EventTypeSetFibreProviderInfo is the event type for setting fibre provider info
	EventTypeSetFibreProviderInfo = "set_fibre_provider_info"

	// AttributeKeyValidatorAddress is the attribute key for consensus address
	AttributeKeyValidatorAddress = "validator_consensus_address"
	// AttributeKeyHost is the attribute key for the fibre host address.
	AttributeKeyHost = "host"

	// MaxHostLen is the maximum length for the host field (IP address, DNS name, etc.)
	MaxHostLen = 100

	// minPort/maxPort define the valid TCP/UDP port range. Port 0 is excluded
	// because it is not a valid listening port — clients connecting to it
	// would fail at the dialer.
	minPort = 1
	maxPort = 65535
)

var _ sdk.Msg = &MsgSetFibreProviderInfo{}

// ValidateBasic performs basic validation of the MsgSetFibreProviderInfo message.
//
// Host must be in `host:port` form: a non-empty DNS name or non-unspecified IP
// literal followed by a numeric port in the range [1, 65535]. Schemes (http://,
// dns:///, etc.) and URL paths are rejected — every fibre client uses the
// same gRPC transport, so per-provider scheme variation has no use case and
// historically led to operators registering hosts that could not be dialled.
func (m *MsgSetFibreProviderInfo) ValidateBasic() error {
	if m.Signer == "" {
		return errorsmod.Wrap(ErrInvalidValidator, "validator address cannot be empty")
	}
	if _, err := sdk.ValAddressFromBech32(m.Signer); err != nil {
		return errorsmod.Wrapf(ErrInvalidValidator, "invalid validator address: %v", err)
	}
	return ValidateHost(m.Host)
}

// ValidateHost enforces the canonical `host:port` form on a fibre provider
// host string. It is exported so off-chain callers (CLI, host registry,
// test helpers) can apply the exact same check the chain enforces.
func ValidateHost(host string) error {
	if host == "" {
		return errorsmod.Wrap(ErrInvalidHostAddress, "host cannot be empty")
	}
	if len(host) > MaxHostLen {
		return errorsmod.Wrapf(ErrInvalidHostAddress,
			"host must be at most %d characters, got %d", MaxHostLen, len(host))
	}

	hostPart, portPart, err := net.SplitHostPort(host)
	if err != nil {
		return errorsmod.Wrapf(ErrInvalidHostAddress,
			"host must be in host:port form, got %q: %v", host, err)
	}
	if hostPart == "" {
		return errorsmod.Wrapf(ErrInvalidHostAddress, "host part cannot be empty in %q", host)
	}
	hostPart = strings.Trim(hostPart, "[]")
	if ip := net.ParseIP(hostPart); ip != nil {
		if ip.IsUnspecified() {
			return errorsmod.Wrapf(ErrInvalidHostAddress, "host part must not be unspecified in %q", host)
		}
	} else if !validDNSName(hostPart) {
		return errorsmod.Wrapf(ErrInvalidHostAddress, "host part must be a DNS name or IP literal in %q", host)
	}
	port, err := strconv.Atoi(portPart)
	if err != nil {
		return errorsmod.Wrapf(ErrInvalidHostAddress,
			"port must be numeric in %q: %v", host, err)
	}
	if port < minPort || port > maxPort {
		return errorsmod.Wrapf(ErrInvalidHostAddress,
			"port %d in %q out of range [%d, %d]", port, host, minPort, maxPort)
	}
	return nil
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
