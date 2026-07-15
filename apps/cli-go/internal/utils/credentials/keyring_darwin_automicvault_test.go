//go:build darwin && automicvault

package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApprovalServiceSigningRequirementPinsTeamAndIdentifier(t *testing.T) {
	require.Contains(t, approvalServiceSigningRequirement, `certificate leaf[subject.OU] = ZU76A67LGU`)
	require.Contains(t, approvalServiceSigningRequirement, `identifier "com.automicvault"`)
	require.NotContains(t, approvalServiceSigningRequirement, "menu-helper")
}

func TestDecodeSecretPlain(t *testing.T) {
	secret, err := decodeSecret("sbp_test")

	require.NoError(t, err)
	require.Equal(t, "sbp_test", secret)
}

func TestDecodeSecretGoKeyringBase64(t *testing.T) {
	encoded := base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte("sbp_test"))

	secret, err := decodeSecret(encoded)

	require.NoError(t, err)
	require.Equal(t, "sbp_test", secret)
}

func TestDecodeSecretGoKeyringHex(t *testing.T) {
	encoded := encodingPrefix + hex.EncodeToString([]byte("sbp_test"))

	secret, err := decodeSecret(encoded)

	require.NoError(t, err)
	require.Equal(t, "sbp_test", secret)
}
