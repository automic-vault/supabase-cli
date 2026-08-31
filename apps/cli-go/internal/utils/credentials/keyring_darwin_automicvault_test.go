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

func TestApprovalDecisionNotice(t *testing.T) {
	require.Equal(t, "automic vault: approved\n", approvalDecisionNotice("approved"))
	require.Equal(t, "automic vault: denied\n", approvalDecisionNotice("denied"))
	require.Empty(t, approvalDecisionNotice("other-decision"))
}

func TestApprovalServiceUnavailableMessage(t *testing.T) {
	require.Equal(t,
		"Automic Vault approval service is blocked by this process's sandbox; retry with elevated permissions",
		approvalServiceUnavailableMessage(true))
	require.Equal(t,
		"Automic Vault approval service is not running; open the menu bar app",
		approvalServiceUnavailableMessage(false))
}

func TestApprovalEventNotice(t *testing.T) {
	require.Equal(t, humanApprovalRequiredNotice, approvalEventNotice(humanApprovalRequiredEvent))
	require.Empty(t, approvalEventNotice("other-event"))
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
