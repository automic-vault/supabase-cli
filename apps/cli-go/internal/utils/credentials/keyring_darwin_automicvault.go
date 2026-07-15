//go:build darwin && automicvault

package credentials

/*
#cgo CFLAGS: -fblocks
#include <xpc/xpc.h>
#include <stdlib.h>

static xpc_type_t av_xpc_type_error(void) {
	return XPC_TYPE_ERROR;
}

static const char *av_xpc_error_description(xpc_object_t object) {
	return xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION);
}

static void av_xpc_connection_set_empty_event_handler(xpc_connection_t connection) {
	xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {});
}
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/zalando/go-keyring"
)

type keyringBackend interface {
	Get(service, account string) (string, error)
	Set(service, account, password string) error
	Delete(service, account string) error
	DeleteAll(service string) error
}

var keyringBackendOverride keyringBackend

const (
	approvalService                   = "com.automicvault.av2.approval"
	approvalServiceSigningRequirement = `anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier "com.automicvault"`
	encodingPrefix                    = "go-keyring-encoded:"
	base64EncodingPrefix              = "go-keyring-base64:"
)

func keyringGet(service, account string) (string, error) {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.Get(service, account)
	}

	key := vaultKey(service, account)
	message := C.xpc_dictionary_create_empty()
	if unsafe.Pointer(message) == nil {
		return "", errors.New("failed to create Automic Vault XPC message")
	}
	defer C.xpc_release(message)

	if err := setString(message, "op", "keys"); err != nil {
		return "", err
	}
	if err := addRequestMetadata(message, service, account, key); err != nil {
		return "", err
	}
	reply, err := send(message)
	if err != nil {
		return "", err
	}
	defer C.xpc_release(reply)
	if err := replyError(reply, "key request denied"); err != nil {
		return "", err
	}

	secretsKey := C.CString("secrets")
	defer C.free(unsafe.Pointer(secretsKey))
	secrets := C.xpc_dictionary_get_value(reply, secretsKey)
	if unsafe.Pointer(secrets) == nil {
		return "", keyring.ErrNotFound
	}
	keyCString := C.CString(key)
	defer C.free(unsafe.Pointer(keyCString))
	value := C.xpc_dictionary_get_string(secrets, keyCString)
	if value == nil {
		return "", keyring.ErrNotFound
	}
	return decodeSecret(C.GoString(value))
}

func keyringSet(service, account, password string) error {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.Set(service, account, password)
	}

	message := C.xpc_dictionary_create_empty()
	if unsafe.Pointer(message) == nil {
		return errors.New("failed to create Automic Vault XPC message")
	}
	defer C.xpc_release(message)

	if err := setString(message, "op", "save"); err != nil {
		return err
	}
	if err := setString(message, "key", vaultKey(service, account)); err != nil {
		return err
	}
	if err := setString(message, "value", password); err != nil {
		return err
	}
	reply, err := send(message)
	if err != nil {
		return err
	}
	defer C.xpc_release(reply)
	return replyError(reply, "secret save failed")
}

func keyringDelete(service, account string) error {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.Delete(service, account)
	}

	message := C.xpc_dictionary_create_empty()
	if unsafe.Pointer(message) == nil {
		return errors.New("failed to create Automic Vault XPC message")
	}
	defer C.xpc_release(message)

	if err := setString(message, "op", "delete"); err != nil {
		return err
	}
	if err := setString(message, "key", vaultKey(service, account)); err != nil {
		return err
	}
	reply, err := send(message)
	if err != nil {
		return err
	}
	defer C.xpc_release(reply)
	return replyError(reply, "secret delete failed")
}

func keyringDeleteAll(service string) error {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.DeleteAll(service)
	}
	return nil
}

func addRequestMetadata(message C.xpc_object_t, service, account, key string) error {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	target, err := os.Executable()
	if err != nil {
		target = "supabase-go"
	} else if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}

	for k, v := range map[string]string{
		"target": target,
		"cwd":    cwd,
		"tool":   "supabase",
		"title":  "Supabase credential requested",
		"detail": tokenRequestDetail(service, account),
	} {
		if err := setString(message, k, v); err != nil {
			return err
		}
	}
	replaceKey := C.CString("replace_existing_env")
	defer C.free(unsafe.Pointer(replaceKey))
	C.xpc_dictionary_set_bool(message, replaceKey, true)
	allowMissingKey := C.CString("allow_missing_keys")
	defer C.free(unsafe.Pointer(allowMissingKey))
	C.xpc_dictionary_set_bool(message, allowMissingKey, false)
	if err := setArray(message, "keys", []string{key}); err != nil {
		return err
	}
	if err := setArray(message, "args", os.Args[1:]); err != nil {
		return err
	}
	return setArray(message, "env_conflicts", nil)
}

func send(message C.xpc_object_t) (C.xpc_object_t, error) {
	service := C.CString(approvalService)
	defer C.free(unsafe.Pointer(service))
	connection := C.xpc_connection_create_mach_service(service, nil, 0)
	if unsafe.Pointer(connection) == nil {
		return nil, errors.New("failed to create Automic Vault XPC connection")
	}
	defer C.xpc_release(C.xpc_object_t(unsafe.Pointer(connection)))
	defer C.xpc_connection_cancel(connection)

	requirement := C.CString(approvalServiceSigningRequirement)
	defer C.free(unsafe.Pointer(requirement))
	if C.xpc_connection_set_peer_code_signing_requirement(connection, requirement) != 0 {
		return nil, errors.New("failed to configure Automic Vault XPC signing requirement")
	}

	C.av_xpc_connection_set_empty_event_handler(connection)
	C.xpc_connection_activate(connection)

	reply := C.xpc_connection_send_message_with_reply_sync(connection, message)
	if unsafe.Pointer(reply) == nil {
		return nil, errors.New("Automic Vault approval did not reply")
	}
	if C.xpc_get_type(reply) == C.av_xpc_type_error() {
		desc := C.av_xpc_error_description(reply)
		err := "Automic Vault XPC connection failed"
		if desc != nil {
			err = C.GoString(desc)
		}
		C.xpc_release(reply)
		if err == "Connection invalid" {
			return nil, errors.New("Automic Vault approval service is not running; open the menu bar app")
		}
		return nil, errors.New(err)
	}
	return reply, nil
}

func replyError(reply C.xpc_object_t, fallback string) error {
	okKey := C.CString("ok")
	defer C.free(unsafe.Pointer(okKey))
	if C.xpc_dictionary_get_bool(reply, okKey) {
		return nil
	}
	errorKey := C.CString("error")
	defer C.free(unsafe.Pointer(errorKey))
	err := C.xpc_dictionary_get_string(reply, errorKey)
	if err == nil {
		return errors.New(fallback)
	}
	message := C.GoString(err)
	if message == "not found" || strings.Contains(message, "-25300") {
		return keyring.ErrNotFound
	}
	return errors.New(message)
}

func setString(dict C.xpc_object_t, key, value string) error {
	keyCString := C.CString(key)
	defer C.free(unsafe.Pointer(keyCString))
	valueCString, err := cStringValue(value)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(valueCString))
	C.xpc_dictionary_set_string(dict, keyCString, valueCString)
	return nil
}

func setArray(dict C.xpc_object_t, key string, values []string) error {
	keyCString := C.CString(key)
	defer C.free(unsafe.Pointer(keyCString))
	array := C.xpc_array_create_empty()
	if unsafe.Pointer(array) == nil {
		return errors.New("failed to create Automic Vault XPC array")
	}
	defer C.xpc_release(array)
	for _, value := range values {
		valueCString, err := cStringValue(value)
		if err != nil {
			return err
		}
		item := C.xpc_string_create(valueCString)
		C.free(unsafe.Pointer(valueCString))
		if unsafe.Pointer(item) == nil {
			return errors.New("failed to create Automic Vault XPC string")
		}
		C.xpc_array_append_value(array, item)
		C.xpc_release(item)
	}
	C.xpc_dictionary_set_value(dict, keyCString, array)
	return nil
}

func cStringValue(value string) (*C.char, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return nil, fmt.Errorf("XPC field contains NUL: %q", value)
	}
	return C.CString(value), nil
}

func tokenRequestDetail(service, account string) string {
	if isAccessTokenAccount(account) {
		return "supabase needs your Supabase access token"
	}
	return fmt.Sprintf("supabase needs the stored Supabase credential for %s", account)
}

func vaultKey(service, account string) string {
	if isAccessTokenAccount(account) {
		return "SUPABASE_ACCESS_TOKEN"
	}
	return "SUPABASE_DB_PASSWORD_" + sanitizeKeyPart(account)
}

func isAccessTokenAccount(account string) bool {
	return account == "supabase" || account == "access-token"
}

func sanitizeKeyPart(value string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToUpper(value) {
		ok := r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if ok {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func decodeSecret(secret string) (string, error) {
	if strings.HasPrefix(secret, encodingPrefix) {
		decoded, err := hex.DecodeString(secret[len(encodingPrefix):])
		return string(decoded), err
	}
	if strings.HasPrefix(secret, base64EncodingPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(secret[len(base64EncodingPrefix):])
		return string(decoded), err
	}
	return secret, nil
}
