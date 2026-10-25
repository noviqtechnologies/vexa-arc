//! OS-level process containment for supervised MCP server children.
//!
//! * **Windows**: the child is created `CREATE_SUSPENDED`, assigned to a Job Object configured with
//!   `KILL_ON_JOB_CLOSE` (and optionally a job memory limit) and only then resumed, so there is no
//!   window in which it (or a grandchild) runs outside the job.
//! * **Unix**: the child gets its own process group; on Linux `PR_SET_PDEATHSIG` is armed (with a
//!   parent-death race check) and an optional address-space `RLIMIT_AS` is applied. The whole group
//!   is killed on `terminate` and when the supervisor is dropped.
//!
//! Limitations: this is process lifetime/resource containment, not a syscall, filesystem or network
//! sandbox. `PR_SET_PDEATHSIG` is Linux-only; on macOS/BSD a hard-killed parent can leave children
//! until their stdin closes.

/// Optional resource limits applied to the supervised process tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContainmentLimits {
    /// Maximum committed memory for the whole job (Windows) or address space per process (Linux).
    pub max_memory_bytes: Option<u64>,
}

#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
mod imp {
    use super::ContainmentLimits;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::ptr;

    type HANDLE = *mut std::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;

    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const JOB_OBJECT_LIMIT_JOB_MEMORY: DWORD = 0x0000_0200;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x0000_2000;
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

    #[link(name = "ntdll")]
    extern "system" {
        /// Resumes all threads of a process created with `CREATE_SUSPENDED` (NTSTATUS, 0 = success).
        fn NtResumeProcess(ProcessHandle: HANDLE) -> i32;
    }

    pub struct OsProcessSupervisor {
        job_handle: HANDLE,
    }

    // Windows handles can be safely transferred across threads
    unsafe impl Send for OsProcessSupervisor {}
    unsafe impl Sync for OsProcessSupervisor {}

    impl OsProcessSupervisor {
        pub fn new() -> std::io::Result<Self> {
            Self::with_limits(ContainmentLimits::default())
        }

        pub fn with_limits(limits: ContainmentLimits) -> std::io::Result<Self> {
            unsafe {
                let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
                if job.is_null() {
                    return Err(std::io::Error::last_os_error());
                }

                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if let Some(bytes) = limits.max_memory_bytes {
                    info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                    info.job_memory_limit = usize::try_from(bytes).unwrap_or(usize::MAX);
                }

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
            // Windows containment is applied by `spawn` (suspended-create + job assignment).
        }

        /// Spawns the command so that it is inside the job object before any of its code runs.
        pub fn spawn(&self, cmd: &mut Command) -> std::io::Result<Child> {
            cmd.creation_flags(CREATE_SUSPENDED);
            let mut child = cmd.spawn()?;
            let handle = child.as_raw_handle() as HANDLE;
            unsafe {
                if AssignProcessToJobObject(self.job_handle, handle) == 0 {
                    let err = std::io::Error::last_os_error();
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(err);
                }
                if NtResumeProcess(handle) != 0 {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::other(
                        "failed to resume contained child process",
                    ));
                }
            }
            Ok(child)
        }

        /// Assigns an already-running child to the job (post-spawn; prefer [`Self::spawn`]).
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
                    // KILL_ON_JOB_CLOSE terminates every process still in the job.
                    CloseHandle(self.job_handle);
                }
            }
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::ContainmentLimits;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::sync::atomic::{AtomicI32, Ordering};

    pub struct OsProcessSupervisor {
        limits: ContainmentLimits,
        /// Process group id of the supervised child (0 = none / already reaped).
        pgid: AtomicI32,
    }

    impl OsProcessSupervisor {
        pub fn new() -> std::io::Result<Self> {
            Self::with_limits(ContainmentLimits::default())
        }

        pub fn with_limits(limits: ContainmentLimits) -> std::io::Result<Self> {
            Ok(Self {
                limits,
                pgid: AtomicI32::new(0),
            })
        }

        pub fn configure_command(&self, cmd: &mut Command) {
            // Put child in its own process group to prevent break-out
            cmd.process_group(0);

            #[cfg(target_os = "linux")]
            {
                // SAFETY: only async-signal-safe libc calls are made between fork and exec.
                let parent_pid = unsafe { libc::getpid() };
                let max_memory = self.limits.max_memory_bytes;
                unsafe {
                    cmd.pre_exec(move || {
                        // Kill child if Arc parent terminates (PR_SET_PDEATHSIG).
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // Close the race where the parent died before PDEATHSIG was armed.
                        if libc::getppid() != parent_pid {
                            return Err(std::io::Error::other(
                                "parent exited before child containment was armed",
                            ));
                        }
                        if let Some(bytes) = max_memory {
                            let lim = libc::rlimit {
                                rlim_cur: bytes as libc::rlim_t,
                                rlim_max: bytes as libc::rlim_t,
                            };
                            if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                        }
                        Ok(())
                    });
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &self.limits;
            }
        }

        /// Spawns the command with containment configured before exec.
        pub fn spawn(&self, cmd: &mut Command) -> std::io::Result<Child> {
            self.configure_command(cmd);
            let child = cmd.spawn()?;
            self.pgid.store(child.id() as i32, Ordering::SeqCst);
            Ok(child)
        }

        pub fn supervise_child(&self, child: &Child) -> std::io::Result<()> {
            self.pgid.store(child.id() as i32, Ordering::SeqCst);
            Ok(())
        }

        fn kill_group(&self) {
            let pgid = self.pgid.swap(0, Ordering::SeqCst);
            if pgid > 0 {
                // SAFETY: plain signal delivery to the child's own process group.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
            }
        }

        pub fn terminate(&self, child: &mut Child) -> std::io::Result<()> {
            // Terminate the entire process group (including grandchildren)
            self.pgid.store(child.id() as i32, Ordering::SeqCst);
            self.kill_group();
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        }
    }

    impl Drop for OsProcessSupervisor {
        fn drop(&mut self) {
            // Covers early-return / panic paths where `terminate` was never reached.
            self.kill_group();
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    use super::ContainmentLimits;
    use std::process::{Child, Command};

    pub struct OsProcessSupervisor;

    impl OsProcessSupervisor {
        pub fn new() -> std::io::Result<Self> {
            Ok(Self)
        }
        pub fn with_limits(_limits: ContainmentLimits) -> std::io::Result<Self> {
            Ok(Self)
        }
        pub fn configure_command(&self, _cmd: &mut Command) {}
        pub fn spawn(&self, cmd: &mut Command) -> std::io::Result<Child> {
            cmd.spawn()
        }
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

    fn sleeper() -> Command {
        #[cfg(windows)]
        {
            let mut cmd = Command::new("cmd.exe");
            cmd.args(["/C", "ping 127.0.0.1 -n 3 > nul"]);
            cmd
        }
        #[cfg(unix)]
        {
            let mut cmd = Command::new("sleep");
            cmd.arg("2");
            cmd
        }
    }

    #[test]
    fn test_os_process_supervisor_lifecycle() {
        let supervisor = OsProcessSupervisor::new().expect("should create supervisor");
        let mut cmd = sleeper();
        let mut child = supervisor
            .spawn(&mut cmd)
            .expect("should spawn contained child");
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "contained child must be running after resume"
        );
        supervisor
            .terminate(&mut child)
            .expect("should terminate child within containment boundary");
        assert!(child.try_wait().expect("try_wait").is_some());
    }

    #[test]
    fn test_legacy_configure_then_supervise_still_works() {
        let supervisor = OsProcessSupervisor::new().expect("should create supervisor");
        let mut cmd = sleeper();
        supervisor.configure_command(&mut cmd);
        let mut child = cmd.spawn().expect("should spawn test child");
        supervisor
            .supervise_child(&child)
            .expect("should assign to containment job");
        supervisor.terminate(&mut child).expect("terminate");
    }

    #[test]
    fn test_spawn_with_memory_limit_runs() {
        let supervisor = OsProcessSupervisor::with_limits(ContainmentLimits {
            // Generous limit: must not prevent a trivial child from starting on any platform.
            max_memory_bytes: Some(4 * 1024 * 1024 * 1024),
        })
        .expect("should create supervisor");
        let mut cmd = sleeper();
        let mut child = supervisor.spawn(&mut cmd).expect("spawn with limit");
        supervisor.terminate(&mut child).expect("terminate");
    }
}
