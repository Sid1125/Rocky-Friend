//! OS-facing adapters that accept only runtime-issued execution permits.

pub mod evidence;
pub mod orchestrate;
pub mod step;

use rocky_domain::CapabilityKind;
use rocky_policy::scope_covers;
use rocky_runtime::{CancellationToken, ExecutionPermit};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReadResult {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// A bounded, read-only executor for a canonicalized filesystem scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemReadExecutor {
    max_bytes: usize,
}

impl FilesystemReadExecutor {
    pub fn new(max_bytes: usize) -> Result<Self, ExecutorError> {
        if max_bytes == 0 {
            return Err(ExecutorError::ZeroByteLimit);
        }
        Ok(Self { max_bytes })
    }

    /// Reads only an existing regular file that remains inside the permit's canonical grant root.
    ///
    /// A cancelled token stops the read before any filesystem access, so work
    /// cancelled after permit issuance still never touches the disk.
    ///
    /// The canonical-scope check is check-then-act: a concurrent writer with
    /// write access to the grant directory itself could swap the path between
    /// validation and open. That writer is already inside the trust boundary
    /// for the granted scope, so this is accepted and documented rather than
    /// solved with platform-specific handle APIs.
    pub fn read(
        &self,
        permit: &ExecutionPermit,
        cancellation: &CancellationToken,
    ) -> Result<FileReadResult, ExecutorError> {
        if cancellation.is_cancelled() {
            return Err(ExecutorError::Cancelled);
        }
        if permit.tool_id() != "filesystem.read"
            || permit.requested_capability().kind != CapabilityKind::FilesystemRead
            || permit.granted_capability().kind != CapabilityKind::FilesystemRead
        {
            return Err(ExecutorError::WrongPermit);
        }
        let root = canonicalize(&permit.granted_capability().scope)?;
        let path = canonicalize(&permit.requested_capability().scope)?;
        if !path.starts_with(&root) {
            return Err(ExecutorError::OutsideGrantedScope);
        }
        if !fs::metadata(&path).map_err(io_error)?.is_file() {
            return Err(ExecutorError::NotAFile);
        }

        let file = File::open(&path).map_err(io_error)?;
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(ExecutorError::NotAFile);
        }
        let mut bytes = Vec::new();
        file.take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > self.max_bytes {
            return Err(ExecutorError::ByteLimitExceeded);
        }
        Ok(FileReadResult { path, bytes })
    }
}

fn canonicalize(path: impl AsRef<Path>) -> Result<PathBuf, ExecutorError> {
    fs::canonicalize(path).map_err(io_error)
}

fn io_error(error: std::io::Error) -> ExecutorError {
    ExecutorError::Io(error.to_string())
}

/// Bounded output of a finished allowlisted program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A process executor that can only run exact allowlist entries.
///
/// There is deliberately no shell in this path: `program` and `args` become
/// OS argv entries directly, so metacharacters such as `;`, `$()`, and
/// backticks stay literal data and can never trigger command substitution.
/// The permit scope must exactly equal `program`, which binds one approval to
/// one executable and leaves argument framing to the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowlistedProcessExecutor {
    allowed: Vec<String>,
    max_output_bytes: usize,
}

impl AllowlistedProcessExecutor {
    /// Creates an executor over exact program strings. An empty allowlist is
    /// valid and denies every program; entries must be non-blank and NUL-free
    /// so no entry can widen matching or panic process spawning. Prefer
    /// absolute paths in the allowlist: bare names resolve via the OS PATH at
    /// spawn time and therefore trust the caller's PATH.
    pub fn new(allowed: Vec<String>, max_output_bytes: usize) -> Result<Self, ExecutorError> {
        if max_output_bytes == 0 {
            return Err(ExecutorError::ZeroByteLimit);
        }
        if allowed
            .iter()
            .any(|entry| entry.trim().is_empty() || entry.contains('\0'))
        {
            return Err(ExecutorError::InvalidAllowlist);
        }
        Ok(Self {
            allowed,
            max_output_bytes,
        })
    }

    /// Runs an allowlisted program with a deadline, output bound, and
    /// cooperative cancellation. Output pipes drain on helper threads while
    /// the caller polls, so a verbose child can never deadlock a full pipe.
    /// The poll loop is bounded by `deadline`; it is not an unbounded loop.
    /// Output is returned only on exit zero; timeouts, cancellations, and
    /// nonzero exits surface as errors without partial output.
    pub fn execute(
        &self,
        permit: &ExecutionPermit,
        program: &str,
        args: &[String],
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutput, ExecutorError> {
        if cancellation.is_cancelled() {
            return Err(ExecutorError::Cancelled);
        }
        if permit.tool_id() != "process.execute"
            || permit.requested_capability().kind != CapabilityKind::ProcessExecute
            || permit.granted_capability().kind != CapabilityKind::ProcessExecute
        {
            return Err(ExecutorError::WrongPermit);
        }
        if !scope_covers(permit.granted_capability(), permit.requested_capability()) {
            return Err(ExecutorError::OutsideGrantedScope);
        }
        // Capability scopes reject NUL bytes at construction, so a NUL-bearing
        // program or argument can never match legitimate input. Reject it as a
        // contract violation instead of reaching `Command`, which would panic.
        if permit.requested_capability().scope != program
            || args != permit.arguments()
            || args.iter().any(|argument| argument.contains('\0'))
        {
            return Err(ExecutorError::ScopeMismatch);
        }
        if !self.allowed.iter().any(|entry| entry == program) {
            return Err(ExecutorError::ProgramNotAllowlisted);
        }
        let deadline = checked_deadline(timeout_ms).ok_or(ExecutorError::InvalidTimeout)?;
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(io_error)?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let limit = self.max_output_bytes as u64 + 1;

        let (end, stdout_result, stderr_result) = std::thread::scope(|scope| {
            let stdout_reader = scope.spawn(|| read_bounded(stdout, limit));
            let stderr_reader = scope.spawn(|| read_bounded(stderr, limit));
            let end = loop {
                if cancellation.is_cancelled() {
                    stop_child(&mut child);
                    break RunEnd::Cancelled;
                }
                match child.try_wait().map_err(io_error) {
                    Err(error) => {
                        stop_child(&mut child);
                        break RunEnd::Failed(error);
                    }
                    Ok(Some(status)) => break RunEnd::Exited(status),
                    Ok(None) => {}
                }
                if Instant::now() >= deadline {
                    stop_child(&mut child);
                    break RunEnd::TimedOut;
                }
                std::thread::sleep(POLL_INTERVAL);
            };
            (end, stdout_reader.join(), stderr_reader.join())
        });
        let stdout = stdout_result
            .map_err(|_| ExecutorError::Io("process output reader failed".into()))
            .and_then(|inner| inner.map_err(io_error))?;
        let stderr = stderr_result
            .map_err(|_| ExecutorError::Io("process output reader failed".into()))
            .and_then(|inner| inner.map_err(io_error))?;
        if stdout.len() > self.max_output_bytes || stderr.len() > self.max_output_bytes {
            return Err(ExecutorError::OutputLimitExceeded);
        }
        match end {
            RunEnd::Cancelled => Err(ExecutorError::Cancelled),
            RunEnd::TimedOut => Err(ExecutorError::Timeout),
            RunEnd::Failed(error) => Err(error),
            RunEnd::Exited(status) => {
                if status.success() {
                    Ok(ProcessOutput {
                        status_code: status.code(),
                        stdout,
                        stderr,
                    })
                } else {
                    Err(ExecutorError::NonZeroExit(status.code()))
                }
            }
        }
    }
}

/// Poll cadence for timeout and cancellation checks while a child runs.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

enum RunEnd {
    Exited(std::process::ExitStatus),
    Cancelled,
    TimedOut,
    Failed(ExecutorError),
}

/// Kills a child and reaps it so no zombie is left behind. Best-effort: the
/// caller already decided the run failed, and a kill that races a natural
/// exit is harmless.
fn stop_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Computes a spawn deadline without panicking on extreme inputs.
/// `Duration::from_millis(u64::MAX)` would panic, so the conversion is
/// checked and overflow surfaces as `None`.
fn checked_deadline(timeout_ms: u64) -> Option<Instant> {
    if timeout_ms == 0 {
        return None;
    }
    let nanos = timeout_ms.checked_mul(1_000_000)?;
    Instant::now().checked_add(Duration::from_nanos(nanos))
}

/// Reads at most `limit` bytes from an optional pipe. `None` only happens if
/// the stdio was not actually piped, which this executor always requests.
fn read_bounded(pipe: Option<impl Read>, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let Some(pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    pipe.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorError {
    ZeroByteLimit,
    WrongPermit,
    OutsideGrantedScope,
    NotAFile,
    ByteLimitExceeded,
    Cancelled,
    InvalidAllowlist,
    ScopeMismatch,
    ProgramNotAllowlisted,
    InvalidTimeout,
    Timeout,
    OutputLimitExceeded,
    NonZeroExit(Option<i32>),
    Io(String),
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "executor error: {self:?}")
    }
}

impl std::error::Error for ExecutorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::{AutonomyLevel, Capability};
    use rocky_policy::Policy;
    use rocky_resources::{ResourceGovernor, ResourceMode};
    use rocky_runtime::{CancellationToken, ExecutionDecision, RuntimeGate};
    use rocky_tools::{ToolBroker, ToolDefinition, ToolRequest};

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rocky-exec-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create test parent");
        }
        fs::write(path, bytes).expect("write test file");
    }

    fn scope(path: &Path) -> Capability {
        Capability::new(
            CapabilityKind::FilesystemRead,
            path.to_str().expect("test path is UTF-8"),
        )
        .expect("valid test capability")
    }

    fn read_gate(grant_scope: &str) -> RuntimeGate {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.read",
                    Capability::new(CapabilityKind::FilesystemRead, grant_scope.to_string())
                        .expect("valid test capability"),
                    AutonomyLevel::A0,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        RuntimeGate::new(broker, ResourceGovernor::new(3))
    }

    fn read_permit(
        gate: &mut RuntimeGate,
        policy: &Policy,
        requested_scope: &str,
    ) -> ExecutionPermit {
        let request = ToolRequest {
            tool_id: "filesystem.read".into(),
            requested_capability: Capability::new(
                CapabilityKind::FilesystemRead,
                requested_scope.to_string(),
            )
            .expect("valid test capability"),
            arguments: Vec::new(),
        };
        match gate
            .issue_permit(
                "task-test",
                0,
                ResourceMode::Normal,
                &request,
                policy,
                &CancellationToken::new(),
            )
            .expect("permit pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => permit,
            other => panic!("expected permit, got {other:?}"),
        }
    }

    fn granting_policy(grant_scope: &str) -> Policy {
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::FilesystemRead, grant_scope.to_string())
                .expect("valid test grant"),
        );
        policy
    }

    #[test]
    fn requires_a_nonzero_read_limit() {
        assert_eq!(
            FilesystemReadExecutor::new(0),
            Err(ExecutorError::ZeroByteLimit)
        );
    }

    #[test]
    fn reads_a_file_authorized_by_a_runtime_permit() {
        let root = test_root("happy");
        let file_path = root.join("hello.txt");
        write_file(&file_path, b"rocky-ok");
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = file_path.to_str().expect("test path is UTF-8").to_string();

        let mut gate = read_gate(&grant);
        let policy = granting_policy(&grant);
        let permit = read_permit(&mut gate, &policy, &requested);

        let result = FilesystemReadExecutor::new(1024)
            .expect("valid limit")
            .read(&permit, &CancellationToken::new())
            .expect("authorized read");
        assert_eq!(result.bytes, b"rocky-ok");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_directories_even_inside_the_grant() {
        let root = test_root("dir");
        let grant = root.to_str().expect("test path is UTF-8").to_string();

        let mut gate = read_gate(&grant);
        let policy = granting_policy(&grant);
        let permit = read_permit(&mut gate, &policy, &grant);

        assert_eq!(
            FilesystemReadExecutor::new(1024)
                .expect("valid limit")
                .read(&permit, &CancellationToken::new()),
            Err(ExecutorError::NotAFile)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn enforces_the_byte_limit() {
        let root = test_root("limit");
        let file_path = root.join("big.txt");
        write_file(&file_path, b"0123456789abcdef");
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = file_path.to_str().expect("test path is UTF-8").to_string();

        let mut gate = read_gate(&grant);
        let policy = granting_policy(&grant);
        let permit = read_permit(&mut gate, &policy, &requested);

        assert_eq!(
            FilesystemReadExecutor::new(4)
                .expect("valid limit")
                .read(&permit, &CancellationToken::new()),
            Err(ExecutorError::ByteLimitExceeded)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_a_permit_issued_for_a_different_tool() {
        let root = test_root("wrong-tool");
        let file_path = root.join("hello.txt");
        write_file(&file_path, b"rocky-ok");
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = file_path.to_str().expect("test path is UTF-8").to_string();

        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.read_alias",
                    scope(&root),
                    AutonomyLevel::A0,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let policy = granting_policy(&grant);
        let request = ToolRequest {
            tool_id: "filesystem.read_alias".into(),
            requested_capability: Capability::new(CapabilityKind::FilesystemRead, requested)
                .expect("valid test capability"),
            arguments: Vec::new(),
        };
        let permit = match gate
            .issue_permit(
                "task-test",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &CancellationToken::new(),
            )
            .expect("permit pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => permit,
            other => panic!("expected permit, got {other:?}"),
        };

        assert_eq!(
            FilesystemReadExecutor::new(1024)
                .expect("valid limit")
                .read(&permit, &CancellationToken::new()),
            Err(ExecutorError::WrongPermit)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reports_missing_files_without_widening_access() {
        let root = test_root("missing");
        let missing = root.join("missing.txt");
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = missing.to_str().expect("test path is UTF-8").to_string();

        let mut gate = read_gate(&grant);
        let policy = granting_policy(&grant);
        let permit = read_permit(&mut gate, &policy, &requested);

        assert!(matches!(
            FilesystemReadExecutor::new(1024)
                .expect("valid limit")
                .read(&permit, &CancellationToken::new()),
            Err(ExecutorError::Io(_))
        ));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cancellation_stops_the_read_before_filesystem_access() {
        let root = test_root("cancelled");
        let file_path = root.join("hello.txt");
        write_file(&file_path, b"rocky-ok");
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = file_path.to_str().expect("test path is UTF-8").to_string();

        let mut gate = read_gate(&grant);
        let policy = granting_policy(&grant);
        let permit = read_permit(&mut gate, &policy, &requested);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert_eq!(
            FilesystemReadExecutor::new(1024)
                .expect("valid limit")
                .read(&permit, &cancellation),
            Err(ExecutorError::Cancelled)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_canonical_escape_through_a_symlink() {
        let root = test_root("link-root");
        let outside = test_root("link-outside");
        let secret = outside.join("secret.txt");
        write_file(&secret, b"secret");
        let link = root.join("link");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).expect("create test symlink");
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(&outside, &link).is_err() {
                // Symlink creation needs elevated privileges on some Windows
                // machines. Policy already blocks `..` traversal, so skip the
                // canonical-escape probe instead of failing the suite.
                let _ = fs::remove_dir_all(&root);
                let _ = fs::remove_dir_all(&outside);
                return;
            }
        }

        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = link
            .join("secret.txt")
            .to_str()
            .expect("test path is UTF-8")
            .to_string();

        let mut gate = read_gate(&grant);
        let policy = granting_policy(&grant);
        let permit = read_permit(&mut gate, &policy, &requested);

        assert_eq!(
            FilesystemReadExecutor::new(1024)
                .expect("valid limit")
                .read(&permit, &CancellationToken::new()),
            Err(ExecutorError::OutsideGrantedScope)
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use rocky_domain::{AutonomyLevel, Capability};
    use rocky_policy::Policy;
    use rocky_resources::{ResourceGovernor, ResourceMode};
    use rocky_runtime::{ExecutionDecision, RuntimeGate};
    use rocky_tools::{ToolBroker, ToolDefinition, ToolRequest};

    fn cargo_path() -> String {
        env!("CARGO").to_string()
    }

    fn process_permit(grant_scope: &str, request_scope: &str, args: &[String]) -> ExecutionPermit {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "process.execute",
                    Capability::new(CapabilityKind::ProcessExecute, grant_scope.to_string())
                        .expect("valid test capability"),
                    AutonomyLevel::A2,
                    30_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::ProcessExecute, grant_scope.to_string())
                .expect("valid test grant"),
        );
        let request = ToolRequest {
            tool_id: "process.execute".into(),
            requested_capability: Capability::new(
                CapabilityKind::ProcessExecute,
                request_scope.to_string(),
            )
            .expect("valid test capability"),
            arguments: args.to_vec(),
        };
        match gate
            .issue_permit(
                "task-test",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &CancellationToken::new(),
            )
            .expect("permit pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => permit,
            other => panic!("expected permit, got {other:?}"),
        }
    }

    fn cargo_permit(args: &[String]) -> ExecutionPermit {
        let cargo = cargo_path();
        process_permit(&cargo, &cargo, args)
    }

    fn cargo_executor() -> AllowlistedProcessExecutor {
        AllowlistedProcessExecutor::new(vec![cargo_path()], 65_536).expect("valid test executor")
    }

    /// A program that runs far longer than any test timeout.
    #[cfg(unix)]
    fn slow_program() -> (String, Vec<String>) {
        ("/bin/sleep".to_string(), vec!["30".to_string()])
    }

    /// A program that runs far longer than any test timeout.
    #[cfg(windows)]
    fn slow_program() -> (String, Vec<String>) {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        (
            format!("{system_root}\\System32\\ping.exe"),
            vec!["-n".to_string(), "30".to_string(), "127.0.0.1".to_string()],
        )
    }

    #[test]
    fn rejects_a_zero_output_bound() {
        assert_eq!(
            AllowlistedProcessExecutor::new(vec![cargo_path()], 0),
            Err(ExecutorError::ZeroByteLimit)
        );
    }

    #[test]
    fn rejects_an_empty_allowlist_entry() {
        assert_eq!(
            AllowlistedProcessExecutor::new(vec![" ".to_string()], 1024),
            Err(ExecutorError::InvalidAllowlist)
        );
    }

    #[test]
    fn runs_an_allowlisted_program() {
        let args = vec!["--version".to_string()];
        let output = cargo_executor()
            .execute(
                &cargo_permit(&args),
                &cargo_path(),
                &args,
                30_000,
                &CancellationToken::new(),
            )
            .expect("allowlisted run");

        assert_eq!(output.status_code, Some(0));
        assert!(output.stdout.starts_with(b"cargo "));
    }

    #[test]
    fn arguments_are_passed_literally_and_never_through_a_shell() {
        let marker = std::env::temp_dir().join(format!("rocky-pwn-{}", std::process::id()));
        let _ = fs::remove_file(&marker);
        let marker_arg = marker.to_str().expect("test path is UTF-8").to_string();
        let args = vec![
            "help".to_string(),
            ";touch".to_string(),
            marker_arg.clone(),
            "$(touch".to_string(),
            marker_arg.clone(),
            ")".to_string(),
            "`touch".to_string(),
            marker_arg,
            "`".to_string(),
        ];

        let result = cargo_executor().execute(
            &cargo_permit(&args),
            &cargo_path(),
            &args,
            30_000,
            &CancellationToken::new(),
        );

        assert!(
            result.is_err(),
            "cargo rejects the unknown help topic, got {result:?}"
        );
        assert!(!marker.exists(), "shell metacharacters must never execute");
        let _ = fs::remove_file(&marker);
    }

    #[test]
    fn substituted_arguments_are_rejected_without_panicking() {
        // The broker already refuses NUL bytes at authorization; here the
        // executor stops substituted arguments at the equality check, before
        // any spawning code could panic on them.
        let args = vec!["--version".to_string()];
        assert_eq!(
            cargo_executor().execute(
                &cargo_permit(&args),
                &cargo_path(),
                &["--version\0".to_string()],
                30_000,
                &CancellationToken::new(),
            ),
            Err(ExecutorError::ScopeMismatch)
        );
    }

    #[test]
    fn rejects_a_program_outside_the_allowlist() {
        let permit = process_permit("prog-x", "prog-x", &[]);

        assert_eq!(
            cargo_executor().execute(&permit, "prog-x", &[], 30_000, &CancellationToken::new(),),
            Err(ExecutorError::ProgramNotAllowlisted)
        );
    }

    #[test]
    fn rejects_a_program_that_differs_from_the_permit_scope() {
        let cargo = cargo_path();
        let permit = process_permit("prog-a", "prog-a", &[]);
        let executor =
            AllowlistedProcessExecutor::new(vec!["prog-a".to_string(), cargo.clone()], 1024)
                .expect("valid test executor");

        assert_eq!(
            executor.execute(&permit, &cargo, &[], 30_000, &CancellationToken::new()),
            Err(ExecutorError::ScopeMismatch)
        );
    }

    #[test]
    fn rejects_a_permit_issued_for_a_different_tool() {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "other.execute",
                    Capability::new(CapabilityKind::ProcessExecute, cargo_path())
                        .expect("valid test capability"),
                    AutonomyLevel::A2,
                    30_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::ProcessExecute, cargo_path())
                .expect("valid test grant"),
        );
        let request = ToolRequest {
            tool_id: "other.execute".into(),
            requested_capability: Capability::new(CapabilityKind::ProcessExecute, cargo_path())
                .expect("valid test capability"),
            arguments: Vec::new(),
        };
        let permit = match gate
            .issue_permit(
                "task-test",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &CancellationToken::new(),
            )
            .expect("permit pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => permit,
            other => panic!("expected permit, got {other:?}"),
        };

        assert_eq!(
            cargo_executor().execute(
                &permit,
                &cargo_path(),
                &["--version".to_string()],
                30_000,
                &CancellationToken::new(),
            ),
            Err(ExecutorError::WrongPermit)
        );
    }

    #[test]
    fn rejects_a_zero_timeout() {
        let args = vec!["--version".to_string()];
        assert_eq!(
            cargo_executor().execute(
                &cargo_permit(&args),
                &cargo_path(),
                &args,
                0,
                &CancellationToken::new(),
            ),
            Err(ExecutorError::InvalidTimeout)
        );
    }

    #[test]
    fn rejects_an_overflowing_timeout_without_panicking() {
        let args = vec!["--version".to_string()];
        assert_eq!(
            cargo_executor().execute(
                &cargo_permit(&args),
                &cargo_path(),
                &args,
                u64::MAX,
                &CancellationToken::new(),
            ),
            Err(ExecutorError::InvalidTimeout)
        );
    }

    #[test]
    fn cancellation_before_spawn_never_starts_the_program() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let args = vec!["--version".to_string()];

        assert_eq!(
            cargo_executor().execute(
                &cargo_permit(&args),
                &cargo_path(),
                &args,
                30_000,
                &cancellation,
            ),
            Err(ExecutorError::Cancelled)
        );
    }

    #[test]
    fn timeout_kills_a_slow_program() {
        let (program, args) = slow_program();
        let executor = AllowlistedProcessExecutor::new(vec![program.clone()], 1024)
            .expect("valid test executor");
        let permit = process_permit(&program, &program, &args);

        assert_eq!(
            executor.execute(&permit, &program, &args, 200, &CancellationToken::new()),
            Err(ExecutorError::Timeout)
        );
    }

    #[test]
    fn cancellation_during_a_run_kills_the_program() {
        let (program, args) = slow_program();
        let executor = AllowlistedProcessExecutor::new(vec![program.clone()], 1024)
            .expect("valid test executor");
        let permit = process_permit(&program, &program, &args);
        let cancellation = CancellationToken::new();
        let canceller = cancellation.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            canceller.cancel();
        });

        let result = executor.execute(&permit, &program, &args, 30_000, &cancellation);
        handle.join().expect("canceller thread joins");

        assert_eq!(result, Err(ExecutorError::Cancelled));
    }

    #[test]
    fn enforces_the_output_limit() {
        let args = vec!["--version".to_string()];
        assert_eq!(
            AllowlistedProcessExecutor::new(vec![cargo_path()], 4)
                .expect("valid test executor")
                .execute(
                    &cargo_permit(&args),
                    &cargo_path(),
                    &args,
                    30_000,
                    &CancellationToken::new(),
                ),
            Err(ExecutorError::OutputLimitExceeded)
        );
    }

    #[test]
    fn maps_a_nonzero_exit_status() {
        let args = vec!["--badflag-rocky-test".to_string()];
        let result = cargo_executor()
            .execute(
                &cargo_permit(&args),
                &cargo_path(),
                &args,
                30_000,
                &CancellationToken::new(),
            )
            .expect_err("unknown flag must fail");

        assert!(
            matches!(result, ExecutorError::NonZeroExit(_)),
            "unexpected result: {result:?}"
        );
    }
}
