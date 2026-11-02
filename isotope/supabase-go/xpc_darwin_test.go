//go:build darwin && automicvault

package main

import (
	"strings"
	"testing"
)

func TestVaultKeys(t *testing.T) {
	for account, expected := range map[string]string{
		"supabase":      "SUPABASE_ACCESS_TOKEN",
		"access-token":  "SUPABASE_ACCESS_TOKEN",
		"project.ref-1": "SUPABASE_DB_PASSWORD_PROJECT_REF_1",
	} {
		if actual := vaultKey(account); actual != expected {
			t.Fatalf("vaultKey(%q) = %q, want %q", account, actual, expected)
		}
	}
}

func TestDecodeSecret(t *testing.T) {
	for encoded, expected := range map[string]string{
		"plain":                           "plain",
		"go-keyring-encoded:736563726574": "secret",
		"go-keyring-base64:c2VjcmV0":      "secret",
	} {
		actual, err := decodeSecret(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatalf("decodeSecret(%q) = %q, want %q", encoded, actual, expected)
		}
	}
}

func TestApprovalServiceRequirement(t *testing.T) {
	for _, expected := range []string{
		`certificate leaf[subject.OU] = ZU76A67LGU`,
		`identifier "com.automicvault"`,
	} {
		if !strings.Contains(approvalServiceSigningRequirement, expected) {
			t.Fatalf("signing requirement does not contain %q", expected)
		}
	}
}
