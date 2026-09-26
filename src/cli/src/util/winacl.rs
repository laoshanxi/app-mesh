//! Windows access control for the OAuth session store. The refresh token file
//! must be accessible by the owning user only, matching the Unix 0o600 mode.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    GetAce, GetAclInformation, GetLengthSid, GetTokenInformation, IsWellKnownSid, TokenUser,
    AclSizeInformation, WinAnonymousSid, WinAuthenticatedUserSid, WinBuiltinGuestsSid,
    WinBuiltinUsersSid, WinWorldSid,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// FILE_ALL_ACCESS: full control for the owning user.
const FILE_ALL_ACCESS: u32 = 0x1F01FF;
// ACCESS_ALLOWED_ACE_TYPE: allow entries are the only ones that can widen access.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
// SUB_CONTAINERS_AND_OBJECTS_INHERIT: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE.
// A directory needs an inheritable entry, or files created inside it start with
// an empty ACL and stay inaccessible to their own owner.
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn win32_error(context: &str, code: u32) -> anyhow::Error {
    anyhow::anyhow!("{}: Windows error {}", context, code)
}

/// The SID bytes of the user running this process, copied out of the token
/// query buffer so the token handle and buffer can be dropped.
struct CurrentUserSid(Vec<u8>);

impl CurrentUserSid {
    fn as_psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }
}

fn current_user_sid() -> Result<CurrentUserSid> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(win32_error("open the process token", GetLastError()));
        }
        let result = (|| {
            let mut length = 0_u32;
            // The first call only sizes the buffer and is expected to fail.
            let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
            if length == 0 {
                bail!("size the process token user: Windows error {}", GetLastError());
            }
            let mut buffer = vec![0_u8; length as usize];
            if GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), length, &mut length) == 0 {
                bail!("read the process token user: Windows error {}", GetLastError());
            }
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = user.User.Sid;
            let sid_length = GetLengthSid(sid) as usize;
            Ok(CurrentUserSid(std::slice::from_raw_parts(sid as *const u8, sid_length).to_vec()))
        })();
        CloseHandle(token);
        result
    }
}

/// Replace the DACL with a single full-control entry for the current user and
/// disable inheritance, so no other principal keeps access to the path.
pub fn restrict_to_current_user(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    // The SID stays alive in `sid` for every call that uses the trustee.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid.as_psid()) };
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: if path.is_dir() { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { NO_INHERITANCE },
        Trustee: trustee,
    };
    let mut acl = std::ptr::null_mut();
    let built = unsafe { SetEntriesInAclW(1, &entry, std::ptr::null_mut(), &mut acl) };
    if built != ERROR_SUCCESS {
        return Err(win32_error("build a private access control list", built));
    }
    let wide = wide_path(path);
    let set = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(acl as _) };
    if set != ERROR_SUCCESS {
        return Err(win32_error(
            &format!("secure permissions on {}", path.display()),
            set,
        ));
    }
    Ok(())
}

/// True when the DACL grants nothing to Everyone, Users, Guests, or Anonymous —
/// the broad principals that would defeat the private-file intent. A missing
/// (NULL) DACL grants everyone full control and never passes.
pub fn is_restricted(path: &Path) -> Result<bool> {
    let wide = wide_path(path);
    let mut dacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let queried = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if queried != ERROR_SUCCESS {
        return Err(win32_error(
            &format!("inspect permissions on {}", path.display()),
            queried,
        ));
    }
    let restricted = if dacl.is_null() {
        false
    } else {
        unsafe { dacl_has_no_broad_grants(dacl) }
    };
    unsafe { LocalFree(descriptor as _) };
    Ok(restricted)
}

/// Walk every allow entry of the DACL; any entry for a well-known broad
/// principal makes the file shared regardless of the granted rights.
unsafe fn dacl_has_no_broad_grants(dacl: *mut windows_sys::Win32::Security::ACL) -> bool {
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(
        dacl,
        &mut info as *mut _ as *mut _,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == 0
    {
        return false;
    }
    for index in 0..info.AceCount {
        let mut ace = std::ptr::null_mut();
        if GetAce(dacl, index, &mut ace) == 0 {
            return false;
        }
        if (*(ace as *const ACE_HEADER)).AceType != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        let sid = &(*(ace as *const ACCESS_ALLOWED_ACE)).SidStart as *const u32 as PSID;
        for well_known in [WinWorldSid, WinBuiltinUsersSid, WinAuthenticatedUserSid, WinAnonymousSid, WinBuiltinGuestsSid] {
            if IsWellKnownSid(sid, well_known) != 0 {
                return false;
            }
        }
    }
    true
}
