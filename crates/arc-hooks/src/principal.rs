use arc_core::event::OsPrincipal;

/// Resolves the OS principal for the current process across Unix, Windows, and other targets.
pub fn current_os_principal() -> OsPrincipal {
    #[cfg(unix)]
    {
        // SAFETY: `libc::getuid()` is always safe to call and has no preconditions.
        let uid = unsafe { libc::getuid() };
        OsPrincipal::Uid(uid)
    }

    #[cfg(windows)]
    {
        if let Some(sid) = windows_current_user_sid() {
            return OsPrincipal::Sid(sid);
        }
        // Do not fall back to environment variables (USERNAME/USERDOMAIN), which are
        // user-modifiable and not a verified OS identity.
        OsPrincipal::Sid("windows-sid-unavailable".to_string())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let user = std::env::var("USER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        OsPrincipal::Sid(user)
    }
}

#[cfg(windows)]
fn windows_current_user_sid() -> Option<String> {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    type Handle = *mut c_void;
    type Bool = i32;
    type Dword = u32;

    const TOKEN_QUERY: Dword = 0x0008;
    const TOKEN_USER_CLASS: Dword = 1;
    const ERROR_INSUFFICIENT_BUFFER: Dword = 122;

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: Dword,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetLastError() -> Dword;
        fn CloseHandle(h_object: Handle) -> Bool;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: Dword,
            token_handle: *mut Handle,
        ) -> Bool;
        fn GetTokenInformation(
            token_handle: Handle,
            token_information_class: Dword,
            token_information: *mut c_void,
            token_information_length: Dword,
            return_length: *mut Dword,
        ) -> Bool;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> Bool;
    }

    unsafe {
        let mut token: Handle = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return None;
        }

        let mut needed: Dword = 0;
        let ok = GetTokenInformation(token, TOKEN_USER_CLASS, null_mut(), 0, &mut needed);
        if ok != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            CloseHandle(token);
            return None;
        }

        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        ) == 0
        {
            CloseHandle(token);
            return None;
        }

        let token_user = &*(buf.as_ptr().cast::<TokenUser>());
        let mut sid_ptr: *mut u16 = null_mut();
        let converted = ConvertSidToStringSidW(token_user.user.sid, &mut sid_ptr);
        CloseHandle(token);

        if converted == 0 || sid_ptr.is_null() {
            return None;
        }

        let mut len = 0usize;
        while *sid_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_ptr, len);
        let sid_str = String::from_utf16_lossy(slice);
        LocalFree(sid_ptr.cast::<c_void>());
        if sid_str.is_empty() {
            None
        } else {
            Some(sid_str)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_os_principal_is_populated() {
        let principal = current_os_principal();
        #[cfg(windows)]
        match principal {
            OsPrincipal::Sid(sid) => assert!(!sid.is_empty(), "expected non-empty Windows SID"),
            other => panic!("expected OsPrincipal::Sid on Windows, got {other:?}"),
        }
        #[cfg(unix)]
        match principal {
            OsPrincipal::Uid(_) => {}
            other => panic!("expected OsPrincipal::Uid on Unix, got {other:?}"),
        }
    }
}
