//go:build darwin && automicvault

package credentials

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *av_security_tool_path = "/usr/bin/security";

static bool av_bytes_contain(const UInt8 *haystack, CFIndex haystack_len, const char *needle) {
	size_t needle_len = strlen(needle);
	if (needle_len == 0 || haystack_len < (CFIndex)needle_len) {
		return false;
	}
	for (CFIndex i = 0; i <= haystack_len - (CFIndex)needle_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0) {
			return true;
		}
	}
	return false;
}

static bool av_trusted_application_is_security_tool(SecTrustedApplicationRef app) {
	CFDataRef data = NULL;
	OSStatus status = SecTrustedApplicationCopyData(app, &data);
	if (status != errSecSuccess || data == NULL) {
		return false;
	}
	const UInt8 *bytes = CFDataGetBytePtr(data);
	CFIndex length = CFDataGetLength(data);
	bool matches = bytes != NULL && av_bytes_contain(bytes, length, av_security_tool_path);
	CFRelease(data);
	return matches;
}

static bool av_acl_authorizes_secret_read(SecACLRef acl) {
	CSSM_ACL_AUTHORIZATION_TAG tags[64];
	uint32 tag_count = 64;
	OSStatus status = SecACLGetAuthorizations(acl, tags, &tag_count);
	if (status != errSecSuccess) {
		return false;
	}
	for (uint32 i = 0; i < tag_count; i++) {
		if (tags[i] == CSSM_ACL_AUTHORIZATION_DECRYPT || tags[i] == CSSM_ACL_AUTHORIZATION_ANY) {
			return true;
		}
	}
	return false;
}

static bool av_acl_allows_security_tool(SecACLRef acl) {
	if (!av_acl_authorizes_secret_read(acl)) {
		return false;
	}

	CFArrayRef app_list = NULL;
	CFStringRef description = NULL;
	SecKeychainPromptSelector prompt_selector = 0;
	OSStatus status = SecACLCopyContents(acl, &app_list, &description, &prompt_selector);
	if (description != NULL) {
		CFRelease(description);
	}
	if (status != errSecSuccess || app_list == NULL) {
		return false;
	}

	CFIndex count = CFArrayGetCount(app_list);
	for (CFIndex i = 0; i < count; i++) {
		SecTrustedApplicationRef app = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(app_list, i);
		if (app != NULL && av_trusted_application_is_security_tool(app)) {
			CFRelease(app_list);
			return true;
		}
	}
	CFRelease(app_list);
	return false;
}

static bool av_item_allows_security_tool(SecKeychainItemRef item) {
	SecAccessRef access = NULL;
	OSStatus status = SecKeychainItemCopyAccess(item, &access);
	if (status != errSecSuccess || access == NULL) {
		return false;
	}

	CFArrayRef acl_list = NULL;
	status = SecAccessCopyACLList(access, &acl_list);
	CFRelease(access);
	if (status != errSecSuccess || acl_list == NULL) {
		return false;
	}

	CFIndex count = CFArrayGetCount(acl_list);
	for (CFIndex i = 0; i < count; i++) {
		SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, i);
		if (acl != NULL && av_acl_allows_security_tool(acl)) {
			CFRelease(acl_list);
			return true;
		}
	}
	CFRelease(acl_list);
	return false;
}

static char *av_copy_item_account(SecKeychainItemRef item) {
	SecKeychainAttribute attrs[1];
	attrs[0].tag = kSecAccountItemAttr;
	attrs[0].length = 0;
	attrs[0].data = NULL;

	SecKeychainAttributeList attr_list;
	attr_list.count = 1;
	attr_list.attr = attrs;

	OSStatus status = SecKeychainItemCopyContent(item, NULL, &attr_list, NULL, NULL);
	if (status != errSecSuccess) {
		return NULL;
	}

	char *account = (char *)malloc(attrs[0].length + 1);
	if (account != NULL) {
		memcpy(account, attrs[0].data, attrs[0].length);
		account[attrs[0].length] = '\0';
	}
	SecKeychainItemFreeContent(&attr_list, NULL);
	return account;
}

static bool av_append_line(char **buffer, size_t *length, size_t *capacity, const char *line) {
	size_t line_len = strlen(line);
	size_t needed = *length + line_len + 2;
	if (needed > *capacity) {
		size_t next_capacity = *capacity == 0 ? 128 : *capacity;
		while (next_capacity < needed) {
			next_capacity *= 2;
		}
		char *next = (char *)realloc(*buffer, next_capacity);
		if (next == NULL) {
			free(*buffer);
			*buffer = NULL;
			*length = 0;
			*capacity = 0;
			return false;
		}
		*buffer = next;
		*capacity = next_capacity;
	}
	memcpy(*buffer + *length, line, line_len);
	*length += line_len;
	(*buffer)[(*length)++] = '\n';
	(*buffer)[*length] = '\0';
	return true;
}

static char *av_copy_insecure_accounts_for_service(const char *service, char **error) {
	size_t service_len = strlen(service);
	SecKeychainAttribute attr;
	attr.tag = kSecServiceItemAttr;
	attr.length = (UInt32)service_len;
	attr.data = (void *)service;

	SecKeychainAttributeList attr_list;
	attr_list.count = 1;
	attr_list.attr = &attr;

	SecKeychainSearchRef search = NULL;
	OSStatus status = SecKeychainSearchCreateFromAttributes(
		NULL,
		kSecGenericPasswordItemClass,
		&attr_list,
		&search
	);
	if (status == errSecItemNotFound) {
		return strdup("");
	}
	if (status != errSecSuccess) {
		asprintf(error, "create keychain search failed with OSStatus %d", (int)status);
		return NULL;
	}

	char *accounts = NULL;
	size_t length = 0;
	size_t capacity = 0;
	while (true) {
		SecKeychainItemRef item = NULL;
		status = SecKeychainSearchCopyNext(search, &item);
		if (status == errSecItemNotFound) {
			break;
		}
		if (status != errSecSuccess) {
			asprintf(error, "copy next keychain item failed with OSStatus %d", (int)status);
			CFRelease(search);
			free(accounts);
			return NULL;
		}
		if (av_item_allows_security_tool(item)) {
			char *account = av_copy_item_account(item);
			if (account != NULL) {
				if (!av_append_line(&accounts, &length, &capacity, account)) {
					free(account);
					CFRelease(item);
					CFRelease(search);
					asprintf(error, "failed to allocate account list");
					return NULL;
				}
				free(account);
			}
		}
		CFRelease(item);
	}
	CFRelease(search);

	if (accounts == NULL) {
		return strdup("");
	}
	return accounts;
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"
)

func MigrateLegacyKeychainItems() (int, error) {
	return migrateLegacyKeychainItems(legacyKeychainMigrator{
		listAccounts:  listLegacyInsecureAccounts,
		readSecret:    securityFindGenericPassword,
		deleteSecret:  securityDeleteGenericPassword,
		restoreSecret: securityAddGenericPassword,
		setSecret:     keyringSet,
	})
}

func listLegacyInsecureAccounts(service string) ([]string, error) {
	serviceC := C.CString(service)
	defer C.free(unsafe.Pointer(serviceC))

	var errorC *C.char
	accountsC := C.av_copy_insecure_accounts_for_service(serviceC, &errorC)
	if accountsC == nil {
		message := "keychain account enumeration failed"
		if errorC != nil {
			defer C.free(unsafe.Pointer(errorC))
			message = C.GoString(errorC)
		}
		return nil, fmt.Errorf("%s", message)
	}
	defer C.free(unsafe.Pointer(accountsC))

	raw := strings.TrimRight(C.GoString(accountsC), "\n")
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

func securityFindGenericPassword(service, account string) (string, error) {
	args := legacySecurityArgs("find-generic-password", "-s", service, "-a", account, "-w")
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		return "", securityCommandError(err, out)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

func securityDeleteGenericPassword(service, account string) error {
	args := legacySecurityArgs("delete-generic-password", "-s", service, "-a", account)
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "could not be found") || strings.Contains(msg, "The specified item could not be found") {
		return nil
	}
	return securityCommandError(err, out)
}

func securityAddGenericPassword(service, account, value string) error {
	args := legacySecurityArgs("add-generic-password", "-U", "-s", service, "-a", account, "-w", value)
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		return securityCommandError(err, out)
	}
	return nil
}

func securityCommandError(err error, output []byte) error {
	msg := strings.TrimSpace(string(output))
	if msg == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, msg)
}

func legacySecurityArgs(args ...string) []string {
	if keychain := legacyLoginKeychainPath(); keychain != "" {
		return append(args, keychain)
	}
	return args
}

func legacyLoginKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	for _, name := range []string{"login.keychain-db", "login.keychain"} {
		path := filepath.Join(home, "Library", "Keychains", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
