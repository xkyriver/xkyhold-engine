//! The few Windows calls the standard library does not wrap.
//!
//! This is the only module of the engine allowed to use `unsafe` (owner's
//! decision, 20 November 2026). Each block calls one Windows function with
//! buffers whose size and lifetime are stated next to it; every handle it
//! opens is closed in the same function. Everything else in the engine
//! stays free of `unsafe`.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION_TYPE, TOKEN_QUERY, TOKEN_USER, TokenElevationType, TokenElevationTypeFull,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_ID_INFO, FileAttributeTagInfo, FileBasicInfo, FileIdInfo,
    GetFileInformationByHandleEx, SetFileAttributesW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// What the backup needs to know about one open file or folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo {
    /// Times in 100 ns units since 1601 (FILETIME), as Windows keeps them.
    pub creation: i64,
    pub last_write: i64,
    pub change: i64,
    pub attributes: u32,
    /// Reparse tag; 0 when the item is not a reparse point.
    pub reparse_tag: u32,
    /// Volume serial number and 128-bit file id: the inode of Windows.
    pub volume: u64,
    pub file_id: u128,
}

/// Reads `T` with `GetFileInformationByHandleEx` for the given class.
///
/// Safety of the call: `file` is an open handle owned by the caller for
/// the whole call; the buffer is a `T` on our stack and its exact size is
/// passed, so Windows writes only inside it. `T` is one of the plain C
/// structs from `windows-sys` that matches `class`, for which all-zero
/// bytes are a valid value.
fn by_handle<T: Default>(file: &File, class: i32) -> io::Result<T> {
    let mut out = T::default();
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            class,
            (&mut out as *mut T).cast::<c_void>(),
            u32::try_from(size_of::<T>()).expect("small struct"),
        )
    };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(out) }
}

/// Times, attributes, reparse tag and file id of an open item. The handle
/// may have been opened with attribute access only.
pub fn file_info(file: &File) -> io::Result<FileInfo> {
    let basic: FILE_BASIC_INFO = by_handle(file, FileBasicInfo)?;
    let tag: FILE_ATTRIBUTE_TAG_INFO = by_handle(file, FileAttributeTagInfo)?;
    let id: FILE_ID_INFO = by_handle(file, FileIdInfo)?;
    let reparse = basic.FileAttributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0;
    Ok(FileInfo {
        creation: basic.CreationTime,
        last_write: basic.LastWriteTime,
        change: basic.ChangeTime,
        attributes: basic.FileAttributes,
        reparse_tag: if reparse { tag.ReparseTag } else { 0 },
        volume: id.VolumeSerialNumber,
        file_id: u128::from_le_bytes(id.FileId.Identifier),
    })
}

/// The access token of this process, closed when dropped.
struct Token(HANDLE);

impl Token {
    fn open() -> io::Result<Self> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // `GetCurrentProcess` returns a pseudo-handle that needs no closing;
        // `handle` receives a real handle, closed in `Drop`.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(Token(handle)) }
    }

    /// Reads token information of `class` into a byte buffer sized by a
    /// first call that asks for the length.
    fn info(&self, class: i32) -> io::Result<Vec<u8>> {
        let mut len = 0u32;
        // Size query: a null buffer of length 0; Windows only writes `len`.
        unsafe { GetTokenInformation(self.0, class, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        // Buffer of u64 so that the structs read from it are aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = unsafe { GetTokenInformation(self.0, class, buf.as_mut_ptr().cast(), len, &mut len) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf.iter().flat_map(|w| w.to_ne_bytes()).take(len as usize).collect())
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // The handle came from `OpenProcessToken` and is closed only here.
        unsafe { CloseHandle(self.0) };
    }
}

/// Whether this process was started with "Run as administrator": elevated
/// through UAC (a full token split from a limited one). With UAC turned
/// off, or for a standard user, this is false (owner's decision, 20
/// November 2026: refuse only an explicit elevation).
pub fn is_elevated() -> bool {
    let Ok(token) = Token::open() else { return false };
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut len = 0u32;
    // The buffer is one `TOKEN_ELEVATION_TYPE` and its exact size is passed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            (&mut kind as *mut TOKEN_ELEVATION_TYPE).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION_TYPE>()).expect("small type"),
            &mut len,
        )
    };
    ok != 0 && kind == TokenElevationTypeFull
}

/// The security identifier of the user running this process, as text
/// (`S-1-5-21-…`).
pub fn current_sid() -> io::Result<String> {
    let token = Token::open()?;
    let mut info = token.info(TokenUser)?;
    // `info` holds a `TOKEN_USER` followed by the SID it points into; the
    // buffer is 8-byte aligned and lives until the end of this function.
    let user = unsafe { &*(info.as_mut_ptr().cast::<TOKEN_USER>()) };
    let mut text: *mut u16 = std::ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // `text` is a NUL-terminated string allocated by Windows with
    // `LocalAlloc`: read up to the NUL, then free it once.
    let sid = unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        sid
    };
    Ok(sid)
}

/// Sets the attributes of a file or folder (hidden, system, read-only…).
pub fn set_attributes(path: &std::path::Path, attributes: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // `wide` is NUL-terminated and outlives the call.
    let ok = unsafe { SetFileAttributesW(wide.as_ptr(), attributes) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Makes `link`, an empty folder that already exists, a junction to the
/// absolute folder `target` (`FSCTL_SET_REPARSE_POINT` with a mount-point
/// reparse buffer). Junctions need no special privilege.
pub fn make_junction(link: &std::path::Path, target: &str) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let target = target.strip_prefix(r"\\?\").unwrap_or(target);
    let substitute: Vec<u16> = format!(r"\??\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let too_long = || io::Error::new(io::ErrorKind::InvalidInput, "junction target too long");
    // Byte lengths of the two names, each followed by a NUL in the buffer.
    let sub_len = u16::try_from(substitute.len() * 2).map_err(|_| too_long())?;
    let print_len = u16::try_from(print.len() * 2).map_err(|_| too_long())?;
    let names_len = u16::try_from(usize::from(sub_len) + usize::from(print_len) + 4).map_err(|_| too_long())?;
    let data_len = names_len.checked_add(8).ok_or_else(too_long)?;

    // REPARSE_DATA_BUFFER, mount-point form, built byte by byte.
    let mut buf: Vec<u8> = Vec::with_capacity(8 + usize::from(data_len));
    buf.extend_from_slice(&TAG_MOUNT_POINT.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&0u16.to_le_bytes()); // substitute name offset
    buf.extend_from_slice(&sub_len.to_le_bytes());
    buf.extend_from_slice(&(sub_len + 2).to_le_bytes()); // print name offset
    buf.extend_from_slice(&print_len.to_le_bytes());
    for unit in substitute.iter().chain(&[0]).chain(&print).chain(&[0]) {
        buf.extend_from_slice(&unit.to_le_bytes());
    }

    let handle = std::fs::OpenOptions::new()
        .access_mode(GENERIC_WRITE)
        .custom_flags(FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT)
        .open(link)?;
    let mut returned = 0u32;
    // `handle` is open for the whole call; `buf` is the complete input
    // buffer with its exact length; there is no output buffer.
    let ok = unsafe {
        DeviceIoControl(
            handle.as_raw_handle() as HANDLE,
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            u32::try_from(buf.len()).map_err(|_| too_long())?,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// `\\?\` in front of an absolute path, so long paths work everywhere.
pub fn verbatim(path: &std::path::Path) -> std::path::PathBuf {
    let text = path.as_os_str();
    if text.to_string_lossy().starts_with(r"\\?\") {
        return path.to_path_buf();
    }
    let mut out = std::ffi::OsString::from(r"\\?\");
    out.push(text);
    std::path::PathBuf::from(out)
}
