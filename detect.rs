use std::path::PathBuf;

const SUPABASE_KEYCHAIN_SERVICE: &str = "Supabase CLI";

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();

    for path in access_token_paths()? {
        if !path.exists() {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if contains_supabase_access_token(&contents) {
            reasons.push(format!(
                "Supabase CLI fallback token file contains plaintext access material: {}",
                path.display()
            ));
        }
    }

    if keychain_allows_security_tool()? {
        reasons.push(
            "Supabase CLI keychain item allows non-interactive extraction by the security tool"
                .to_string(),
        );
    }

    Ok(reasons)
}

fn access_token_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(home) = std::env::var_os("SUPABASE_HOME").filter(|value| !value.is_empty()) {
        return Ok(vec![PathBuf::from(home).join("access-token")]);
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(vec![home.join(".supabase/access-token")])
}

fn contains_supabase_access_token(contents: &str) -> bool {
    let token = contents.trim();
    token.starts_with("sbp_") && token.len() >= 44
}

#[cfg(all(target_os = "macos", not(coverage)))]
fn keychain_allows_security_tool() -> Result<bool, String> {
    macos_keychain::keychain_allows_security_tool(SUPABASE_KEYCHAIN_SERVICE)
}

#[cfg(any(not(target_os = "macos"), coverage))]
fn keychain_allows_security_tool() -> Result<bool, String> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct EnvGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn set(values: &[(&'static str, Option<&str>)]) -> Self {
            let previous = values
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    match value {
                        Some(value) => unsafe { std::env::set_var(key, value) },
                        None => unsafe { std::env::remove_var(key) },
                    }
                    (*key, previous)
                })
                .collect();
            Self { previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.previous.drain(..).rev() {
                match previous {
                    Some(value) => unsafe { std::env::set_var(key, value) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    #[test]
    fn detects_plaintext_fallback_token() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let token_fixture = format!("{}{}\n", "sbp_", "a".repeat(40));
        fs::write(temp.path().join("access-token"), token_fixture).unwrap();
        let _env = EnvGuard::set(&[
            ("SUPABASE_HOME", Some(temp.path().to_str().unwrap())),
            ("HOME", Some(temp.path().to_str().unwrap())),
        ]);

        let reasons = install_insecurity_reasons().unwrap();

        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("fallback token file")),
            "expected fallback token reason, got {reasons:?}"
        );
    }

    #[test]
    fn ignores_empty_or_non_supabase_fallback_token() {
        assert!(!contains_supabase_access_token(""));
        assert!(!contains_supabase_access_token("not-a-token"));
        assert!(!contains_supabase_access_token("sbp_short"));
    }

    #[test]
    fn uses_supabase_home_before_default_home() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let explicit = temp.path().join("explicit");
        fs::create_dir_all(&explicit).unwrap();
        let _env = EnvGuard::set(&[
            ("SUPABASE_HOME", Some(explicit.to_str().unwrap())),
            ("HOME", Some(temp.path().to_str().unwrap())),
        ]);

        assert_eq!(
            access_token_paths().unwrap(),
            vec![explicit.join("access-token")]
        );
    }
}

#[cfg(all(target_os = "macos", not(coverage)))]
mod macos_keychain {
    use std::ffi::c_void;
    use std::ptr;

    const ERR_SEC_SUCCESS: i32 = 0;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const CSSM_ACL_AUTHORIZATION_ANY: i32 = 1;
    const CSSM_ACL_AUTHORIZATION_DECRYPT: i32 = 24;
    const SEC_GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
    const SEC_SERVICE_ITEM_ATTR: u32 = u32::from_be_bytes(*b"svce");
    const SECURITY_TOOL_PATH: &[u8] = b"/usr/bin/security";

    type CFTypeRef = *const c_void;
    type CFArrayRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFStringRef = *const c_void;
    type SecAccessRef = *const c_void;
    type SecACLRef = *const c_void;
    type SecKeychainItemRef = *const c_void;
    type SecKeychainSearchRef = *const c_void;
    type SecTrustedApplicationRef = *const c_void;

    #[repr(C)]
    struct SecKeychainAttribute {
        tag: u32,
        length: u32,
        data: *mut c_void,
    }

    #[repr(C)]
    struct SecKeychainAttributeList {
        count: u32,
        attr: *mut SecKeychainAttribute,
    }

    unsafe extern "C" {
        fn CFArrayGetCount(array: CFArrayRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CFArrayRef, index: isize) -> *const c_void;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> isize;
        fn CFRelease(value: CFTypeRef);
        fn SecACLCopyContents(
            acl: SecACLRef,
            application_list: *mut CFArrayRef,
            description: *mut CFStringRef,
            prompt_selector: *mut u16,
        ) -> i32;
        fn SecACLGetAuthorizations(acl: SecACLRef, tags: *mut i32, tag_count: *mut u32) -> i32;
        fn SecAccessCopyACLList(access: SecAccessRef, acl_list: *mut CFArrayRef) -> i32;
        fn SecKeychainItemCopyAccess(item: SecKeychainItemRef, access: *mut SecAccessRef) -> i32;
        fn SecKeychainSearchCopyNext(
            search: SecKeychainSearchRef,
            item: *mut SecKeychainItemRef,
        ) -> i32;
        fn SecKeychainSearchCreateFromAttributes(
            keychain_or_array: CFTypeRef,
            item_class: u32,
            attr_list: *const SecKeychainAttributeList,
            search: *mut SecKeychainSearchRef,
        ) -> i32;
        fn SecTrustedApplicationCopyData(
            app: SecTrustedApplicationRef,
            data: *mut CFDataRef,
        ) -> i32;
    }

    pub(super) fn keychain_allows_security_tool(service: &str) -> Result<bool, String> {
        let mut service_bytes = service.as_bytes().to_vec();
        let mut attr = SecKeychainAttribute {
            tag: SEC_SERVICE_ITEM_ATTR,
            length: service_bytes.len() as u32,
            data: service_bytes.as_mut_ptr().cast(),
        };
        let attr_list = SecKeychainAttributeList {
            count: 1,
            attr: &mut attr,
        };
        let mut search = ptr::null();
        let status = unsafe {
            SecKeychainSearchCreateFromAttributes(
                ptr::null(),
                SEC_GENERIC_PASSWORD_ITEM_CLASS,
                &attr_list,
                &mut search,
            )
        };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(false);
        }
        check_status(status, "create keychain search")?;
        let _search_ref = ScopedCf(search);

        loop {
            let mut item = ptr::null();
            let status = unsafe { SecKeychainSearchCopyNext(search, &mut item) };
            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(false);
            }
            check_status(status, "copy next keychain item")?;
            let _item_ref = ScopedCf(item);
            if item_allows_security_tool(item)? {
                return Ok(true);
            }
        }
    }

    fn item_allows_security_tool(item: SecKeychainItemRef) -> Result<bool, String> {
        let mut access = ptr::null();
        let status = unsafe { SecKeychainItemCopyAccess(item, &mut access) };
        check_status(status, "copy keychain item access")?;
        let _access_ref = ScopedCf(access);

        let mut acl_list = ptr::null();
        let status = unsafe { SecAccessCopyACLList(access, &mut acl_list) };
        check_status(status, "copy keychain ACL list")?;
        let _acl_list_ref = ScopedCf(acl_list);

        let acl_count = unsafe { CFArrayGetCount(acl_list) };
        for index in 0..acl_count {
            let acl = unsafe { CFArrayGetValueAtIndex(acl_list, index).cast::<c_void>() };
            if acl.is_null() {
                continue;
            }
            if acl_allows_security_tool(acl)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acl_allows_security_tool(acl: SecACLRef) -> Result<bool, String> {
        if !acl_authorizes_secret_read(acl) {
            return Ok(false);
        }

        let mut app_list = ptr::null();
        let mut description = ptr::null();
        let mut prompt_selector = 0u16;
        let status = unsafe {
            SecACLCopyContents(acl, &mut app_list, &mut description, &mut prompt_selector)
        };
        check_status(status, "copy keychain ACL contents")?;
        let _description_ref = ScopedCf(description);
        if app_list.is_null() {
            return Ok(false);
        }
        let _app_list_ref = ScopedCf(app_list);

        let app_count = unsafe { CFArrayGetCount(app_list) };
        for index in 0..app_count {
            let app = unsafe { CFArrayGetValueAtIndex(app_list, index).cast::<c_void>() };
            if app.is_null() {
                continue;
            }
            if trusted_application_is_security_tool(app)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acl_authorizes_secret_read(acl: SecACLRef) -> bool {
        let mut tags = [0i32; 64];
        let mut tag_count = tags.len() as u32;
        let status = unsafe { SecACLGetAuthorizations(acl, tags.as_mut_ptr(), &mut tag_count) };
        if status != ERR_SEC_SUCCESS {
            return false;
        }
        tags.iter()
            .take(tag_count as usize)
            .copied()
            .any(auth_tag_grants_secret_read)
    }

    fn auth_tag_grants_secret_read(tag: i32) -> bool {
        tag == CSSM_ACL_AUTHORIZATION_DECRYPT || tag == CSSM_ACL_AUTHORIZATION_ANY
    }

    fn trusted_application_is_security_tool(app: SecTrustedApplicationRef) -> Result<bool, String> {
        let mut data = ptr::null();
        let status = unsafe { SecTrustedApplicationCopyData(app, &mut data) };
        check_status(status, "copy trusted application data")?;
        let _data_ref = ScopedCf(data);

        let bytes = cf_data_bytes(data);
        Ok(bytes
            .windows(SECURITY_TOOL_PATH.len())
            .any(|window| window == SECURITY_TOOL_PATH))
    }

    fn cf_data_bytes(data: CFDataRef) -> Vec<u8> {
        let length = unsafe { CFDataGetLength(data) };
        if length <= 0 {
            return Vec::new();
        }
        let ptr = unsafe { CFDataGetBytePtr(data) };
        if ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr, length as usize).to_vec() }
    }

    fn check_status(status: i32, context: &str) -> Result<(), String> {
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(format!("{context} failed with OSStatus {status}"))
        }
    }

    struct ScopedCf<T>(*const T);

    impl<T> Drop for ScopedCf<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0.cast()) };
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn read_authorization_tags_cover_decrypt_and_any_only() {
            assert!(auth_tag_grants_secret_read(CSSM_ACL_AUTHORIZATION_DECRYPT));
            assert!(auth_tag_grants_secret_read(CSSM_ACL_AUTHORIZATION_ANY));
            assert!(!auth_tag_grants_secret_read(0));
        }
    }
}
