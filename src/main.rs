use std::ffi::c_void;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::Diagnostics::Debug::*,
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::System::LibraryLoader::*,
    Win32::System::Memory::*,
    Win32::System::Threading::*,
    Win32::UI::Controls::Dialogs::*,
};

const OSU_NAME: &str = "osu!.exe";

#[derive(Serialize, Deserialize)]
struct Config {
    osu_path: String,
}

fn log_info(msg: &str) {
    println!("[INFO] {}", msg);
}

fn log_error(msg: &str) {
    eprintln!("[ERROR] {}", msg);
}

// Helper to convert Rust string to null-terminated wide string (PCWSTR)
fn to_pcwstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn inject_dll(h_proc: HANDLE, path: &str) -> bool {
    let kernel32 = GetModuleHandleA(s!("Kernel32.dll"));
    if kernel32.is_err() {
        log_error(&format!("Failed to get kernel32.dll handle: {:?}", kernel32.err()));
        return false;
    }
    let kernel32 = kernel32.unwrap();

    let load_library = GetProcAddress(kernel32, s!("LoadLibraryA"));
    if load_library.is_none() {
        log_error("Failed to get LoadLibraryA address");
        return false;
    }

    let path_len = path.len() + 1;
    let lp_base_address = VirtualAllocEx(
        h_proc,
        None,
        path_len,
        MEM_COMMIT,
        PAGE_READWRITE,
    );

    if lp_base_address.is_null() {
        log_error(&format!("Failed to allocate memory in target process: {:?}", GetLastError()));
        return false;
    }

    let mut bytes_written = 0;
    let path_cstr = std::ffi::CString::new(path).unwrap();
    if WriteProcessMemory(
        h_proc,
        lp_base_address,
        path_cstr.as_ptr() as *const c_void,
        path_len,
        Some(&mut bytes_written),
    ).is_err() {
        log_error(&format!("Failed to write dll name to target process: {:?}", GetLastError()));
        return false;
    }

    let h_thread = CreateRemoteThread(
        h_proc,
        None,
        0,
        Some(std::mem::transmute(load_library)),
        Some(lp_base_address),
        0,
        None,
    );

    if h_thread.is_err() {
        log_error(&format!("Failed to create remote thread: {:?}", h_thread.err()));
        return false;
    }
    let h_thread = h_thread.unwrap();

    WaitForSingleObject(h_thread, INFINITE);
    let _ = CloseHandle(h_thread);
    let _ = VirtualFreeEx(h_proc, lp_base_address, 0, MEM_RELEASE);

    true
}

unsafe fn get_pid_by_name(name: &str) -> u32 {
    let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if h_snapshot.is_err() {
        return 0;
    }
    let h_snapshot = h_snapshot.unwrap();

    let mut pe = PROCESSENTRY32W::default();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(h_snapshot, &mut pe).is_ok() {
        loop {
            let exe_file = String::from_utf16_lossy(&pe.szExeFile);
            let exe_file = exe_file.trim_matches(char::from(0));
            if exe_file == name {
                let _ = CloseHandle(h_snapshot);
                return pe.th32ProcessID;
            }

            if Process32NextW(h_snapshot, &mut pe).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(h_snapshot);
    0
}

unsafe fn get_exe_dir() -> PathBuf {
    std::env::current_exe()
        .map(|p| p.parent().unwrap().to_path_buf())
        .unwrap_or_else(|_| std::env::current_dir().unwrap())
}

unsafe fn get_osu_path() -> Option<PathBuf> {
    let config_path = get_exe_dir().join("config.toml");
    
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(&config_path) {
            if let Ok(config) = toml::from_str::<Config>(&content) {
                let path = PathBuf::from(config.osu_path);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }

    // Open dialog
    let mut ofn = OPENFILENAMEW::default();
    let mut sz_file = [0u16; 260];
    let filter = to_pcwstr("osu!.exe\0osu!.exe\0");
    let title = to_pcwstr("Select osu!.exe");

    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = HWND(0);
    ofn.lpstrFilter = PCWSTR(filter.as_ptr());
    ofn.lpstrFile = PWSTR(sz_file.as_mut_ptr());
    ofn.nMaxFile = sz_file.len() as u32;
    ofn.lpstrTitle = PCWSTR(title.as_ptr());
    ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;

    if GetOpenFileNameW(&mut ofn).as_bool() {
        let len = sz_file.iter().position(|&c| c == 0).unwrap_or(sz_file.len());
        let path_str = String::from_utf16_lossy(&sz_file[..len]);
        let path = PathBuf::from(&path_str);

        let config = Config {
            osu_path: path_str.clone(),
        };
        
        if let Ok(toml_str) = toml::to_string(&config) {
            let _ = fs::write(config_path, toml_str);
        }

        return Some(path);
    }

    None
}

fn main() {
    unsafe {
        let dll_path = get_exe_dir().join("Downloader.dll");
        if !dll_path.exists() {
             // Just for testing, we might assume it exists or warn
             log_info(&format!("Warning: Downloader.dll not found at {}", dll_path.display()));
        }
        let dll_path_str = dll_path.to_str().unwrap();

        let pid = get_pid_by_name(OSU_NAME);
        
        if pid != 0 {
            log_info(&format!("osu! found, pid: {}", pid));
            let h_proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if let Ok(h_proc) = h_proc {
                log_info("Injecting dll...");
                log_info(&format!("DLL path: {}", dll_path_str));
                if inject_dll(h_proc, dll_path_str) {
                    log_info("Dll injected successfully");
                }
                let _ = CloseHandle(h_proc);
            } else {
                log_error(&format!("Failed to open process, error code: {:?}", GetLastError()));
            }
        } else {
            let osu_path = get_osu_path();
            if osu_path.is_none() {
                log_error("Cannot find osu!.exe!");
                thread::sleep(Duration::from_secs(3));
                return;
            }
            let osu_path = osu_path.unwrap();
            log_info(&format!("osu! path: {}", osu_path.display()));

            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();

            let cmd_line = to_pcwstr(osu_path.to_str().unwrap());
            let dir = to_pcwstr(osu_path.parent().unwrap().to_str().unwrap());

            // Start suspended
            if CreateProcessW(
                None,
                PWSTR(cmd_line.as_ptr() as *mut _),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                PCWSTR(dir.as_ptr()),
                &mut si,
                &mut pi,
            ).is_err() {
                log_error(&format!("Failed to start osu!, error code: {:?}", GetLastError()));
                thread::sleep(Duration::from_secs(3));
                return;
            }

            if inject_dll(pi.hProcess, dll_path_str) {
                log_info("Dll injected successfully");
            }

            ResumeThread(pi.hThread);
            
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }

        thread::sleep(Duration::from_secs(3));
    }
}
