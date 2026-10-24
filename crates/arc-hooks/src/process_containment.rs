#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
mod imp {
    use std::os::windows::io::AsRawHandle;
    use std::process::{Child, Command};
    use std::ptr;

    type HANDLE = *mut std::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;
    #[allow(non_upper_case_globals)]
    const JobObjectExtendedLimitInformation: DWORD = 9;

    #[repr(C)]
    struct IO_COUNTERS {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: DWORD,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: DWORD,
        affinity: usize,
        priority_class: DWORD,
        scheduling_class: DWORD,
    }

    #[repr(C)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        io_info: IO_COUNTERS,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_limit: usize,
        peak_job_memory_limit: usize,
    }

    extern "system" {
        fn CreateJobObjectW(lpJobAttributes: *mut std::ffi::c_void, lpName: *const u16) -> HANDLE;
        fn SetInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: DWORD,
            lpJobObjectInformation: *const std::ffi::c_void,
            cbJobObjectInformationLength: DWORD,
        ) -> BOOL;
        fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
        fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    pub struct OsProcessSupervisor {
        job_handle: HANDLE,
    }

    // Windows handles can be safely transferred across threads
    unsafe impl Send for OsProcessSupervisor {}
    unsafe impl Sync for OsProcessSupervisor {}

    impl OsProcessSupervisor {
        pub fn new() -> std::io::Result<Self> {
            unsafe {
                let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
                if job.is_null() {
                    return Err(std::io::Error::last_os_error());
                }

                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                let ok = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
                );

                if ok == 0 {
                    let err = std::io::Error::last_os_error();
                    CloseHandle(job);
                    return Err(err);
                }

                Ok(Self { job_handle: job })
            }
        }

        pub fn configure_command(&self, _cmd: &mut Command) {
            // Windows Job Object containment is applied post-spawn to child handle
        }

        pub fn supervise_child(&self, child: &Child) -> std::io::Result<()> {
            unsafe {
                let proc_handle = child.as_raw_handle() as HANDLE;
                let ok = AssignProcessToJobObject(self.job_handle, proc_handle);
                if ok == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }
        }

        pub fn terminate(&self, child: &mut Child) -> std::io::Result<()> {
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        }
    }

    impl Drop for OsProcessSupervisor {
        fn drop(&mut self) {
            unsafe {
                if !self.job_handle.is_null() {
                    CloseHandle(self.job_handle);
                }
            }
        }
    }
}

#[cfg(unix)]
mod imp {
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    pub struct OsProcessSupervisor {
        _private: (),
    }

    impl OsProcessSupervisor {
        pub fn new() -> std::io::Result<Self> {
            Ok(Self { _private: () })
        }

        pub fn configure_command(&self, cmd: &mut Command) {
            // Put child in its own process group to prevent break-out
            cmd.process_group(0);

            #[cfg(target_os = "linux")]
            unsafe {
                cmd.pre_exec(|| {
                    // Instruct Linux kernel to kill child if Arc parent terminates (PR_SET_PDEATHSIG)
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                    Ok(())
                });
            }
        }

        pub fn supervise_child(&self, _child: &Child) -> std::io::Result<()> {
            Ok(())
        }

        pub fn terminate(&self, child: &mut Child) -> std::io::Result<()> {
            let pid = child.id() as i32;
            unsafe {
                // Terminate the entire process group
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    use std::process::{Child, Command};

    pub struct OsProcessSupervisor;

    impl OsProcessSupervisor {
        pub fn new() -> std::io::Result<Self> {
            Ok(Self)
        }
        pub fn configure_command(&self, _cmd: &mut Command) {}
        pub fn supervise_child(&self, _child: &Child) -> std::io::Result<()> {
            Ok(())
        }
        pub fn terminate(&self, child: &mut Child) -> std::io::Result<()> {
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        }
    }
}

pub use imp::OsProcessSupervisor;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_os_process_supervisor_lifecycle() {
        let supervisor = OsProcessSupervisor::new().expect("should create supervisor");

        #[cfg(windows)]
        let mut cmd = Command::new("cmd.exe");
        #[cfg(windows)]
        cmd.args(["/C", "ping 127.0.0.1 -n 2 > nul"]);

        #[cfg(unix)]
        let mut cmd = Command::new("sleep");
        #[cfg(unix)]
        cmd.arg("1");

        supervisor.configure_command(&mut cmd);
        let mut child = cmd.spawn().expect("should spawn test child");
        supervisor
            .supervise_child(&child)
            .expect("should assign to containment job");

        supervisor
            .terminate(&mut child)
            .expect("should terminate child within containment boundary");
    }
}
