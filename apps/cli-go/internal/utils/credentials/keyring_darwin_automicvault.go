//go:build darwin && automicvault

package credentials

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

static OSStatus create_access_for_path(const char *path, CFStringRef descriptor, SecAccessRef *accessRef) {
	SecTrustedApplicationRef app = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(path, &app);
	if (status != errSecSuccess) {
		return status;
	}

	const void *trustedApps[] = { app };
	CFArrayRef trustedList = CFArrayCreate(kCFAllocatorDefault, trustedApps, 1, &kCFTypeArrayCallBacks);
	status = SecAccessCreate(descriptor, trustedList, accessRef);
	CFRelease(trustedList);
	CFRelease(app);
	return status;
}

static OSStatus create_generic_password_item(
	const char *service, UInt32 serviceLen,
	const char *account, UInt32 accountLen,
	const char *label, UInt32 labelLen,
	const void *secret, UInt32 secretLen,
	SecAccessRef accessRef,
	SecKeychainItemRef *itemRef
) {
	SecKeychainAttribute attrs[3];
	attrs[0].tag = kSecServiceItemAttr;
	attrs[0].length = serviceLen;
	attrs[0].data = (void *)service;
	attrs[1].tag = kSecAccountItemAttr;
	attrs[1].length = accountLen;
	attrs[1].data = (void *)account;
	attrs[2].tag = kSecLabelItemAttr;
	attrs[2].length = labelLen;
	attrs[2].data = (void *)label;

	SecKeychainAttributeList attrList;
	attrList.count = 3;
	attrList.attr = attrs;

	return SecKeychainItemCreateFromContent(
		kSecGenericPasswordItemClass,
		&attrList,
		secretLen,
		secret,
		NULL,
		accessRef,
		itemRef
	);
}
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
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
	encodingPrefix       = "go-keyring-encoded:"
	base64EncodingPrefix = "go-keyring-base64:"
	errSecItemNotFound   = -25300
)

func keyringGet(service, account string) (string, error) {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.Get(service, account)
	}

	query := itemQuery(service, account)
	defer C.CFRelease(C.CFTypeRef(query))

	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecReturnData),
		unsafe.Pointer(C.kCFBooleanTrue),
	)
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecMatchLimit),
		unsafe.Pointer(C.kSecMatchLimitOne),
	)

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if err := keychainError(status); err != nil {
		return "", err
	}
	defer C.CFRelease(result)

	secret := cfDataString(C.CFDataRef(result))
	return decodeSecret(secret)
}

func keyringSet(service, account, password string) error {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.Set(service, account, password)
	}

	access, err := trustedApplicationAccess(service)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	status := createGenericPasswordItem(service, account, password, access)
	if status != C.errSecDuplicateItem {
		return keychainError(status)
	}
	if err := keyringDelete(service, account); err != nil {
		return err
	}
	return keychainError(createGenericPasswordItem(service, account, password, access))
}

func keyringDelete(service, account string) error {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.Delete(service, account)
	}

	query := itemQuery(service, account)
	defer C.CFRelease(C.CFTypeRef(query))

	return keychainError(C.SecItemDelete(C.CFDictionaryRef(query)))
}

func keyringDeleteAll(service string) error {
	if keyringBackendOverride != nil {
		return keyringBackendOverride.DeleteAll(service)
	}

	query := serviceQuery(service)
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(C.CFDictionaryRef(query))
	if status == C.OSStatus(errSecItemNotFound) {
		return nil
	}
	return keychainError(status)
}

func itemQuery(service, account string) C.CFMutableDictionaryRef {
	query := serviceQuery(service)

	accountString := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountString))
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecAttrAccount),
		unsafe.Pointer(accountString),
	)

	return query
}

func serviceQuery(service string) C.CFMutableDictionaryRef {
	query := C.CFDictionaryCreateMutable(
		C.CFAllocatorRef(0),
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecClass),
		unsafe.Pointer(C.kSecClassGenericPassword),
	)

	serviceString := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceString))
	C.CFDictionarySetValue(
		query,
		unsafe.Pointer(C.kSecAttrService),
		unsafe.Pointer(serviceString),
	)

	return query
}

func trustedApplicationAccess(descriptor string) (C.SecAccessRef, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable path: %w", err)
	}
	if resolvedPath, err := filepath.EvalSymlinks(executablePath); err == nil {
		executablePath = resolvedPath
	}

	cPath := C.CString(executablePath)
	defer C.free(unsafe.Pointer(cPath))

	descriptorString := cfString(descriptor)
	defer C.CFRelease(C.CFTypeRef(descriptorString))

	var access C.SecAccessRef
	status := C.create_access_for_path(cPath, descriptorString, &access)
	if err := keychainError(status); err != nil {
		return 0, err
	}

	return access, nil
}

func createGenericPasswordItem(service, account, password string, access C.SecAccessRef) C.OSStatus {
	serviceBytes := []byte(service)
	accountBytes := []byte(account)
	labelBytes := []byte(service)
	secretBytes := []byte(password)

	var servicePtr, accountPtr, labelPtr, secretPtr unsafe.Pointer
	if len(serviceBytes) > 0 {
		servicePtr = C.CBytes(serviceBytes)
		defer C.free(servicePtr)
	}
	if len(accountBytes) > 0 {
		accountPtr = C.CBytes(accountBytes)
		defer C.free(accountPtr)
	}
	if len(labelBytes) > 0 {
		labelPtr = C.CBytes(labelBytes)
		defer C.free(labelPtr)
	}
	if len(secretBytes) > 0 {
		secretPtr = C.CBytes(secretBytes)
		defer C.free(secretPtr)
	}

	var item C.SecKeychainItemRef
	status := C.create_generic_password_item(
		(*C.char)(servicePtr), C.UInt32(len(serviceBytes)),
		(*C.char)(accountPtr), C.UInt32(len(accountBytes)),
		(*C.char)(labelPtr), C.UInt32(len(labelBytes)),
		secretPtr, C.UInt32(len(secretBytes)),
		access,
		&item,
	)
	if item != 0 {
		C.CFRelease(C.CFTypeRef(item))
	}
	return status
}

func cfString(s string) C.CFStringRef {
	bytes := []byte(s)
	if len(bytes) == 0 {
		return C.CFStringCreateWithBytes(C.CFAllocatorRef(0), nil, 0, C.kCFStringEncodingUTF8, 0)
	}
	return C.CFStringCreateWithBytes(
		C.CFAllocatorRef(0),
		(*C.UInt8)(unsafe.Pointer(&bytes[0])),
		C.CFIndex(len(bytes)),
		C.kCFStringEncodingUTF8,
		0,
	)
}

func cfDataString(data C.CFDataRef) string {
	length := C.CFDataGetLength(data)
	if length == 0 {
		return ""
	}
	ptr := C.CFDataGetBytePtr(data)
	return string(C.GoBytes(unsafe.Pointer(ptr), C.int(length)))
}

func keychainError(status C.OSStatus) error {
	switch status {
	case C.errSecSuccess:
		return nil
	case C.OSStatus(errSecItemNotFound):
		return keyring.ErrNotFound
	default:
		return fmt.Errorf("keychain error: %d", int(status))
	}
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
