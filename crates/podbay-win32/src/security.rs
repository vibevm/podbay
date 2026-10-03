//! Shared explicit logon-SID security descriptors for Windows pod resources.
use crate::Win32Error;
use crate::pipe_model::protected_sddl;
use crate::windows::OwnedHandle;
use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, TOKEN_GROUPS, TOKEN_QUERY, TokenLogonSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) struct LocalAllocation(*mut c_void);
impl LocalAllocation {
    pub(crate) fn raw(&self) -> *mut c_void {
        self.0
    }
}
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: pointer came from a Win32 LocalAlloc-producing conversion.
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(crate) fn pipe_descriptor() -> Result<LocalAllocation, Win32Error> {
    let sid = current_logon_sid()?;
    let sddl = protected_sddl(&sid)?;
    descriptor_from_sddl(&sddl)
}
pub(crate) fn directory_descriptor() -> Result<LocalAllocation, Win32Error> {
    let sid = current_logon_sid()?;
    protected_sddl(&sid)?; // validates exact S-1-5-5-X-Y shape
    descriptor_from_sddl(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
}
fn descriptor_from_sddl(sddl: &str) -> Result<LocalAllocation, Win32Error> {
    let wide = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: NUL-terminated SDDL and writable descriptor output live through
    // conversion; LocalFree owns the result after success.
    let okay = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if okay == 0 || descriptor.is_null() {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    Ok(LocalAllocation(descriptor))
}
fn current_logon_sid() -> Result<String, Win32Error> {
    let mut raw: HANDLE = null_mut();
    // SAFETY: current process pseudo handle is borrowed; token handle output
    // is immediately owned by the RAII wrapper.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let token = OwnedHandle::new(raw)?;
    let mut bytes = 0_u32;
    // SAFETY: first call asks only for the required byte count.
    unsafe {
        GetTokenInformation(token.raw(), TokenLogonSid, null_mut(), 0, &mut bytes);
    }
    if (bytes as usize) < std::mem::size_of::<TOKEN_GROUPS>() || bytes > 4_096 {
        return Err(Win32Error::Unsupported("logon SID unavailable"));
    }
    let mut storage = vec![0_usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: usize-aligned storage has the required byte count and lives
    // through the query and SID conversion below.
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenLogonSid,
            storage.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
    {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    // SAFETY: successful TokenLogonSid returns a TOKEN_GROUPS header; bound
    // and alignment were checked, and one logon SID is required.
    let groups = unsafe { &*(storage.as_ptr().cast::<TOKEN_GROUPS>()) };
    if groups.GroupCount != 1 || groups.Groups[0].Sid.is_null() {
        return Err(Win32Error::Unsupported("exact logon SID unavailable"));
    }
    let mut sid_ptr = null_mut();
    // SAFETY: SID points into the live token-information buffer; output is a
    // LocalFree-owned NUL-terminated UTF-16 string.
    if unsafe { ConvertSidToStringSidW(groups.Groups[0].Sid, &mut sid_ptr) } == 0
        || sid_ptr.is_null()
    {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let _sid_allocation = LocalAllocation(sid_ptr.cast());
    let mut length = 0_usize;
    // SAFETY: conversion produced a NUL-terminated string; 80 code units is
    // a strict upper bound for the expected S-1-5-5-X-Y logon SID.
    while length < 80 && unsafe { *sid_ptr.add(length) } != 0 {
        length += 1;
    }
    if length == 80 {
        return Err(Win32Error::Invalid("logon SID exceeds bound"));
    }
    // SAFETY: the first `length` UTF-16 code units are inside the live string.
    String::from_utf16(unsafe { std::slice::from_raw_parts(sid_ptr, length) })
        .map_err(|_| Win32Error::Invalid("logon SID encoding"))
}
