//go:build security_review

package types_test

import (
	"testing"

	"github.com/celestiaorg/celestia-app/v9/x/valaddr/types"
	"github.com/stretchr/testify/assert"
)

func TestSecurityReviewValidateHostAllowsDNSAndRejectsUnusableHosts(t *testing.T) {
	assert.NoError(t, types.ValidateHost("validator.example.com:7980"))

	for _, host := range []string{
		"0.0.0.0:7980",
		"[::]:7980",
		"bad_host.example.com:7980",
	} {
		assert.Error(t, types.ValidateHost(host), host)
	}
}
