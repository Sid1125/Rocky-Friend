//! Provider-agnostic model contracts.
//!
//! Model output is data. It has no dependency on policy, tools, executors, or OS access.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Local,
    Cloud,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRequest {
    pub task_id: String,
    pub prompt: String,
    pub max_output_tokens: u32,
    pub tools: Vec<RequestedTool>,
}

impl ModelRequest {
    pub fn new(
        task_id: impl Into<String>,
        prompt: impl Into<String>,
        max_output_tokens: u32,
        tools: Vec<RequestedTool>,
    ) -> Result<Self, ModelError> {
        let task_id = task_id.into();
        let prompt = prompt.into();
        if task_id.trim().is_empty() || prompt.trim().is_empty() || max_output_tokens == 0 {
            return Err(ModelError::InvalidRequest);
        }
        let mut names = Vec::with_capacity(tools.len());
        for tool in &tools {
            if names.contains(&tool.name) {
                return Err(ModelError::InvalidRequest);
            }
            names.push(tool.name.clone());
        }
        Ok(Self {
            task_id,
            prompt,
            max_output_tokens,
            tools,
        })
    }
}

/// One tool a model may propose, described for the model. The description
/// and schema shape proposals; they grant nothing — the broker, gate, and
/// invocation table remain the only authority paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestedTool {
    pub name: String,
    pub description: String,
    pub arguments_schema: String,
}

impl RequestedTool {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        arguments_schema: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        let description = description.into();
        let arguments_schema = arguments_schema.into();
        if name.trim().is_empty()
            || description.trim().is_empty()
            || arguments_schema.trim().is_empty()
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            name,
            description,
            arguments_schema,
        })
    }
}

/// A model-proposed tool call. Arguments ride as discrete values, never a
/// shell string: splitting happens in no trusted component, so there is
/// nothing to misquote. The tool broker still bounds and validates them, and
/// the requested scope comes from the invocation table, never the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedToolCall {
    pub tool_id: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelResponse {
    pub text: String,
    pub proposed_tools: Vec<ProposedToolCall>,
}

/// A provider receives bounded input and returns untrusted data.
pub trait ModelProvider {
    fn kind(&self) -> ProviderKind;
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError>;
}

/// Routes only to explicitly enabled provider classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelRouter {
    cloud_enabled: bool,
}

impl ModelRouter {
    pub fn new(cloud_enabled: bool) -> Self {
        Self { cloud_enabled }
    }

    pub fn select(&self, requested: ProviderKind) -> Result<ProviderKind, ModelError> {
        if requested == ProviderKind::Cloud && !self.cloud_enabled {
            return Err(ModelError::CloudDisabled);
        }
        Ok(requested)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    InvalidRequest,
    CloudDisabled,
    ProviderUnavailable,
    SecretPresent,
    InvalidSecret,
    TooManySecrets,
    BudgetExceeded,
    ProviderSaturated,
    PromptTooLong,
    TooManyExcerpts,
    MalformedReply,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "model error: {self:?}")
    }
}

impl std::error::Error for ModelError {}

/// A localhost Ollama provider: the first runnable local brain.
///
/// Talks to Ollama's `/api/chat` over plain HTTP on loopback only —
/// non-loopback endpoints are rejected at construction, so a misconfigured
/// endpoint can never turn the "local" provider into a cloud exfiltration
/// path. Timeouts bound every call; cancellation between calls stays the
/// orchestrator's job, exactly like every other provider.
#[derive(Clone, Debug)]
pub struct OllamaProvider {
    endpoint: String,
    model: String,
    agent: ureq::Agent,
}

impl OllamaProvider {
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        timeout_ms: u64,
    ) -> Result<Self, ModelError> {
        let endpoint = endpoint.into();
        let model = model.into();
        if !is_loopback_endpoint(&endpoint) {
            return Err(ModelError::InvalidRequest);
        }
        if model.trim().is_empty() || timeout_ms == 0 {
            return Err(ModelError::InvalidRequest);
        }
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        Ok(Self {
            endpoint,
            model,
            agent,
        })
    }

    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.endpoint.trim_end_matches('/'))
    }
}

impl ModelProvider for OllamaProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Local
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let tools: Vec<serde_json::Value> = request
            .tools
            .iter()
            .map(|tool| {
                // The arguments schema rides inside the description: Ollama's
                // tool protocol takes no free-form schema field, so the text
                // the model actually reads carries it.
                let description =
                    format!("{}\nArguments: {}", tool.description, tool.arguments_schema);
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": description,
                        "parameters": {"type": "object", "properties": {}},
                    }
                })
            })
            .collect();
        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "messages": [{"role": "user", "content": request.prompt}],
            "tools": tools,
            "options": {"num_predict": request.max_output_tokens},
        });
        let reply: serde_json::Value = self
            .agent
            .post(&self.chat_url())
            .send_json(body)
            .map_err(|_| ModelError::ProviderUnavailable)?
            .into_json()
            .map_err(|_| ModelError::MalformedReply)?;
        let (text, proposed_tools) = map_chat_reply(&reply)?;
        Ok(ModelResponse {
            text,
            proposed_tools,
        })
    }
}

/// Accepts only `http(s)://` loopback endpoints: `localhost`, `127.0.0.1`,
/// or `[::1]`, with any port. Anything else — remote hosts, missing
/// schemes, unix sockets — is rejected so local-provider traffic can never
/// leave the machine by misconfiguration.
fn is_loopback_endpoint(endpoint: &str) -> bool {
    let host = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"));
    let Some(host) = host else {
        return false;
    };
    // Bracketed IPv6 first: a naive split on ':' would stop inside the
    // address (`[::1]` would parse as `[`). Anything unbracketed splits on
    // the port or path separator as usual.
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host.split([':', '/']).next().unwrap_or_default()
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Maps an Ollama chat reply to text plus tool proposals. Argument objects
/// serialize key-sorted for determinism: string values pass through raw so
/// `"--force"` stays `--force`, while numbers and nested values keep their
/// JSON text. Anything off-shape is `MalformedReply`, never a guess.
fn map_chat_reply(
    reply: &serde_json::Value,
) -> Result<(String, Vec<ProposedToolCall>), ModelError> {
    let message = reply.get("message").ok_or(ModelError::MalformedReply)?;
    let text = message
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or(ModelError::MalformedReply)?
        .to_string();
    let mut proposed_tools = Vec::new();
    if let Some(calls) = message.get("tool_calls") {
        let calls = calls.as_array().ok_or(ModelError::MalformedReply)?;
        for call in calls {
            let function = call.get("function").ok_or(ModelError::MalformedReply)?;
            let name = function
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or(ModelError::MalformedReply)?
                .to_string();
            let mut arguments = Vec::new();
            if let Some(parameters) = function.get("arguments") {
                let object = parameters.as_object().ok_or(ModelError::MalformedReply)?;
                let mut keys: Vec<&String> = object.keys().collect();
                keys.sort();
                for key in keys {
                    let value = &object[key];
                    match value {
                        serde_json::Value::String(text) => arguments.push(text.clone()),
                        _ => arguments.push(value.to_string()),
                    }
                }
            }
            proposed_tools.push(ProposedToolCall {
                tool_id: name,
                arguments,
            });
        }
    }
    Ok((text, proposed_tools))
}

/// Maximum evidence excerpts per assembled prompt. Excerpts are bounded
/// elsewhere by content, but their count is a prompt-assembly concern: one
/// excerpt per finding keeps prompts proportional to board size.
pub const MAX_EXCERPTS: usize = 16;

/// Assembles a task prompt with stable section framing.
///
/// Format stability is a contract with the model: sections always appear in
/// GOAL / CONSTRAINTS / EVIDENCE order with fixed markers, so parsing stays
/// out of the picture entirely. Empty sections are omitted rather than left
/// blank. Oversized assemblies fail instead of truncating: silent truncation
/// drops evidence the model then confidently invents around.
pub fn build_task_prompt(
    goal: &str,
    constraints: &[String],
    excerpts: &[String],
    max_chars: usize,
) -> Result<String, ModelError> {
    if excerpts.len() > MAX_EXCERPTS {
        return Err(ModelError::TooManyExcerpts);
    }
    let mut prompt = String::from("GOAL\n");
    prompt.push_str(goal);
    if !constraints.is_empty() {
        prompt.push_str("\n\nCONSTRAINTS");
        for constraint in constraints {
            prompt.push_str("\n- ");
            prompt.push_str(constraint);
        }
    }
    if !excerpts.is_empty() {
        prompt.push_str("\n\nEVIDENCE");
        for (index, excerpt) in excerpts.iter().enumerate() {
            prompt.push_str(&format!("\n[{}] {excerpt}", index + 1));
        }
    }
    if prompt.chars().count() > max_chars {
        return Err(ModelError::PromptTooLong);
    }
    Ok(prompt)
}

/// Maximum key length for stored secrets. Service/account names are short
/// labels, never documents; the values they point at carry no length bound
/// because the OS backend enforces its own.
pub const MAX_KEY_CHARS: usize = 256;

/// A persisted secret value boundary: callers name secrets, backends hold
/// them. Only two backends exist: memory (tests and ephemeral use) and the
/// OS credential store (everything real).
pub trait SecretStore {
    fn store_secret(&mut self, key: &str, value: &str) -> Result<(), SecretError>;
    fn load_secret(&self, key: &str) -> Result<Option<String>, SecretError>;
    /// Deletes a secret, returning whether one existed. Absence is not an
    /// error: delete-then-confirm flows must not fail on the confirm.
    fn delete_secret(&mut self, key: &str) -> Result<bool, SecretError>;
}

fn checked_key(key: &str) -> Result<(), SecretError> {
    if key.trim().is_empty() {
        return Err(SecretError::EmptyKey);
    }
    if key.chars().count() > MAX_KEY_CHARS {
        return Err(SecretError::KeyTooLong);
    }
    Ok(())
}

/// In-memory secret store for tests and ephemeral use. Values live in plain
/// process memory with no locking or persistence: never the real backend.
#[derive(Clone, Default)]
pub struct InMemorySecretStore {
    secrets: std::collections::BTreeMap<String, String>,
}

impl fmt::Debug for InMemorySecretStore {
    /// Never prints secret values: even debug logs must not carry them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemorySecretStore")
            .field("keys", &self.secrets.len())
            .finish()
    }
}

impl SecretStore for InMemorySecretStore {
    fn store_secret(&mut self, key: &str, value: &str) -> Result<(), SecretError> {
        checked_key(key)?;
        if value.is_empty() {
            return Err(SecretError::EmptySecret);
        }
        self.secrets.insert(key.into(), value.into());
        Ok(())
    }

    fn load_secret(&self, key: &str) -> Result<Option<String>, SecretError> {
        checked_key(key)?;
        Ok(self.secrets.get(key).cloned())
    }

    fn delete_secret(&mut self, key: &str) -> Result<bool, SecretError> {
        checked_key(key)?;
        Ok(self.secrets.remove(key).is_some())
    }
}

/// OS-backed secret store (Credential Manager / Secret Service / Keychain
/// via the `keyring` crate). Values never touch ROCKY's database, logs, or
/// prompts except through explicit caller reads.
///
/// Platform support is not uniform. Windows and macOS request a real
/// `keyring` backend in this crate's manifest; Linux does not yet, so there
/// `keyring` resolves to its mock store, which accepts a write and then
/// reports no entry. Callers on Linux must use [`InMemorySecretStore`] until
/// a backend is chosen (`docs/plans/DEPENDENCY_REVIEW.md`).
#[derive(Clone, Debug)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>) -> Result<Self, SecretError> {
        let service = service.into();
        if service.trim().is_empty() {
            return Err(SecretError::EmptyKey);
        }
        Ok(Self { service })
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, SecretError> {
        checked_key(key)?;
        keyring::Entry::new(&self.service, key)
            .map_err(|error| SecretError::Store(error.to_string()))
    }
}

impl SecretStore for KeyringSecretStore {
    fn store_secret(&mut self, key: &str, value: &str) -> Result<(), SecretError> {
        if value.is_empty() {
            return Err(SecretError::EmptySecret);
        }
        self.entry(key)?
            .set_password(value)
            .map_err(|error| SecretError::Store(error.to_string()))
    }

    fn load_secret(&self, key: &str) -> Result<Option<String>, SecretError> {
        use keyring::Error as KeyringError;
        match self.entry(key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(SecretError::Store(error.to_string())),
        }
    }

    fn delete_secret(&mut self, key: &str) -> Result<bool, SecretError> {
        use keyring::Error as KeyringError;
        match self.entry(key)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(error) => Err(SecretError::Store(error.to_string())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretError {
    EmptyKey,
    KeyTooLong,
    EmptySecret,
    Store(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "secret error: {self:?}")
    }
}

impl std::error::Error for SecretError {}

/// Caps concurrent inference use without blocking.
///
/// Logical workers may stay concurrent while inference serializes: this gate
/// hands out a bounded number of RAII permits, and a saturated provider
/// reports `ProviderSaturated` so the scheduler can queue, shrink context,
/// or degrade instead of piling on. The gate never blocks, so it cannot
/// deadlock a worker loop.
#[derive(Clone, Debug)]
pub struct InferenceGate {
    max_in_flight: usize,
    in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl InferenceGate {
    pub fn new(max_in_flight: usize) -> Result<Self, ModelError> {
        if max_in_flight == 0 {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            max_in_flight,
            in_flight: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Takes a permit if one is free, releasing it when the guard drops.
    pub fn acquire(&self) -> Result<InferenceGuard<'_>, ModelError> {
        use std::sync::atomic::Ordering;
        let mut current = self.in_flight.load(Ordering::SeqCst);
        loop {
            if current >= self.max_in_flight {
                return Err(ModelError::ProviderSaturated);
            }
            match self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Ok(InferenceGuard { gate: self });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// A held inference slot. Dropping frees it, so early returns and panics
/// cannot leak capacity.
#[derive(Debug)]
pub struct InferenceGuard<'a> {
    gate: &'a InferenceGate,
}

impl Drop for InferenceGuard<'_> {
    fn drop(&mut self) {
        self.gate
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A fixed context window split into prompt space and a completion reserve.
///
/// The reserve guarantees the model always has room to answer: a prompt that
/// would eat into it is rejected instead of silently truncating the reply.
/// All arithmetic is checked, so hostile token estimates fail as errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextBudget {
    total_tokens: u32,
    reserved_for_completion: u32,
}

impl ContextBudget {
    pub fn new(total_tokens: u32, reserved_for_completion: u32) -> Result<Self, ModelError> {
        if total_tokens == 0
            || reserved_for_completion == 0
            || reserved_for_completion > total_tokens
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            total_tokens,
            reserved_for_completion,
        })
    }

    /// Returns the completion allowance for an estimated prompt size, or
    /// rejects the prompt when it would breach the reserve.
    pub fn plan(&self, prompt_tokens: u32) -> Result<u32, ModelError> {
        let used = prompt_tokens
            .checked_add(self.reserved_for_completion)
            .ok_or(ModelError::BudgetExceeded)?;
        if used > self.total_tokens {
            return Err(ModelError::BudgetExceeded);
        }
        Ok(self.total_tokens - used)
    }
}

/// Maximum caller-declared secrets per guard. Matching is exact-substring
/// work linear in this list, so the bound keeps prompt checks cheap.
pub const MAX_SECRETS: usize = 64;

/// Replacement text for redacted secrets. A fixed marker avoids leaking the
/// secret's length through the redacted output.
pub const REDACTED_MARKER: &str = "[REDACTED]";

/// Guards model prompts against caller-declared secrets.
///
/// Matching is exact-substring only: the guard finds secrets the caller
/// names, nothing more. It is not a secret detector, and heuristic pattern
/// matching is deliberately absent — a detector that misses is worse than
/// none, because callers stop checking. Undeclared secrets stay the caller's
/// responsibility; this type only makes declared ones impossible to forget.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptGuard {
    secrets: Vec<String>,
}

impl fmt::Debug for PromptGuard {
    /// Never prints secret values: even debug logs must not carry them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptGuard")
            .field("declared", &self.secrets.len())
            .finish()
    }
}

impl PromptGuard {
    /// Declares secrets by exact value. Entries must be non-blank (a blank
    /// "secret" would match everywhere) and the list must stay bounded.
    /// Longer secrets sort first so redaction replaces the longest match.
    pub fn new(mut secrets: Vec<String>) -> Result<Self, ModelError> {
        if secrets.len() > MAX_SECRETS {
            return Err(ModelError::TooManySecrets);
        }
        if secrets.iter().any(|secret| secret.trim().is_empty()) {
            return Err(ModelError::InvalidSecret);
        }
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        Ok(Self { secrets })
    }

    /// Rejects a prompt containing any declared secret.
    pub fn check(&self, prompt: &str) -> Result<(), ModelError> {
        if self.secrets.iter().any(|secret| prompt.contains(secret)) {
            return Err(ModelError::SecretPresent);
        }
        Ok(())
    }

    /// Returns the prompt with every declared secret replaced.
    /// Redaction is a backstop for logs and telemetry, not a license to send
    /// secrets toward providers: prefer `check` at the provider boundary.
    pub fn redact(&self, prompt: &str) -> String {
        let mut redacted = prompt.to_string();
        for secret in &self.secrets {
            redacted = redacted.replace(secret, REDACTED_MARKER);
        }
        redacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_routing_requires_explicit_enablement() {
        let router = ModelRouter::new(false);
        assert_eq!(
            router.select(ProviderKind::Cloud),
            Err(ModelError::CloudDisabled)
        );
        assert_eq!(router.select(ProviderKind::Local), Ok(ProviderKind::Local));
    }

    #[test]
    fn requests_require_bounded_nonempty_input() {
        assert_eq!(
            ModelRequest::new("task-1", "prompt", 0, Vec::new()),
            Err(ModelError::InvalidRequest)
        );
    }

    fn read_tool() -> RequestedTool {
        RequestedTool::new(
            "filesystem.read",
            "Read a file inside the grant",
            r#"{"path": "file path"}"#,
        )
        .expect("valid test tool")
    }

    #[test]
    fn requested_tools_reject_blanks_and_duplicates() {
        assert_eq!(
            RequestedTool::new("  ", "desc", "schema"),
            Err(ModelError::InvalidRequest)
        );
        assert_eq!(
            ModelRequest::new("task-1", "prompt", 10, vec![read_tool(), read_tool()]),
            Err(ModelError::InvalidRequest)
        );
        assert!(ModelRequest::new("task-1", "prompt", 10, vec![read_tool()]).is_ok());
    }

    fn guard() -> PromptGuard {
        PromptGuard::new(vec!["sk-live-abc".into(), "token-xyz".into()]).expect("valid test guard")
    }

    #[test]
    fn prompt_guard_detects_declared_secrets() {
        assert_eq!(guard().check("summarize this"), Ok(()));
        assert_eq!(
            guard().check("use key sk-live-abc now"),
            Err(ModelError::SecretPresent)
        );
    }

    #[test]
    fn prompt_guard_redacts_longest_match_first() {
        let redacted = guard().redact("a sk-live-abc b token-xyz c");
        assert_eq!(redacted, "a [REDACTED] b [REDACTED] c");
        assert!(!redacted.contains("sk-live"));
        assert!(!redacted.contains("token-xyz"));
    }

    #[test]
    fn prompt_guard_rejects_empty_and_unbounded_secret_lists() {
        assert_eq!(
            PromptGuard::new(vec!["  ".into()]),
            Err(ModelError::InvalidSecret)
        );
        assert_eq!(
            PromptGuard::new(vec!["s".to_string(); MAX_SECRETS + 1]),
            Err(ModelError::TooManySecrets)
        );
    }

    #[test]
    fn prompt_guard_debug_never_prints_secrets() {
        let rendered = format!("{:?}", guard());
        assert!(!rendered.contains("sk-live-abc"));
        assert!(!rendered.contains("token-xyz"));
    }

    fn budget() -> ContextBudget {
        ContextBudget::new(4_000, 1_000).expect("valid test budget")
    }

    #[test]
    fn context_budget_reports_the_completion_allowance() {
        assert_eq!(budget().plan(2_500), Ok(500));
        assert_eq!(budget().plan(3_000), Ok(0));
    }

    #[test]
    fn context_budget_rejects_over_budget_prompts() {
        assert_eq!(budget().plan(3_001), Err(ModelError::BudgetExceeded));
    }

    #[test]
    fn context_budget_rejects_overflow_without_panicking() {
        assert_eq!(budget().plan(u32::MAX), Err(ModelError::BudgetExceeded));
    }

    #[test]
    fn context_budget_rejects_unusable_construction() {
        assert_eq!(ContextBudget::new(0, 100), Err(ModelError::InvalidRequest));
        assert_eq!(
            ContextBudget::new(500, 501),
            Err(ModelError::InvalidRequest)
        );
        assert_eq!(ContextBudget::new(500, 0), Err(ModelError::InvalidRequest));
    }

    #[test]
    fn inference_gate_caps_concurrent_use() {
        let gate = InferenceGate::new(2).expect("valid test gate");
        let _first = gate.acquire().expect("first slot");
        let _second = gate.acquire().expect("second slot");
        assert_eq!(gate.acquire().err(), Some(ModelError::ProviderSaturated));
    }

    #[test]
    fn inference_guard_frees_its_slot_on_drop() {
        let gate = InferenceGate::new(1).expect("valid test gate");
        {
            let _only = gate.acquire().expect("only slot");
            assert_eq!(gate.acquire().err(), Some(ModelError::ProviderSaturated));
        }
        assert!(gate.acquire().is_ok());
    }

    #[test]
    fn inference_gate_rejects_a_zero_cap() {
        assert_eq!(
            InferenceGate::new(0).err(),
            Some(ModelError::InvalidRequest)
        );
    }

    #[test]
    fn inference_gate_never_exceeds_its_cap_across_threads() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let gate = InferenceGate::new(2).expect("valid test gate");
        let high_water = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| {
                    // The gate never blocks: losers retry until a holder's
                    // guard drops, which always happens because holders
                    // sleep briefly and return.
                    let _permit = loop {
                        match gate.acquire() {
                            Ok(permit) => break permit,
                            Err(ModelError::ProviderSaturated) => {
                                std::thread::yield_now();
                            }
                            Err(unexpected) => {
                                panic!("unexpected acquire error: {unexpected:?}")
                            }
                        }
                    };
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    high_water.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        assert!(high_water.load(Ordering::SeqCst) <= 2);
    }

    fn secret_store() -> InMemorySecretStore {
        InMemorySecretStore::default()
    }

    #[test]
    fn secrets_round_trip_and_delete() {
        let mut store = secret_store();
        assert_eq!(store.load_secret("api-key").expect("load"), None);
        store
            .store_secret("api-key", "sk-live-abc")
            .expect("store secret");
        assert_eq!(
            store.load_secret("api-key").expect("load"),
            Some("sk-live-abc".to_string())
        );
        // Overwriting updates in place; deleting reports what happened.
        store
            .store_secret("api-key", "sk-live-def")
            .expect("overwrite secret");
        assert_eq!(
            store.load_secret("api-key").expect("load"),
            Some("sk-live-def".to_string())
        );
        assert!(store.delete_secret("api-key").expect("delete"));
        assert!(!store.delete_secret("api-key").expect("delete"));
    }

    #[test]
    fn secrets_reject_blank_keys_and_empty_values() {
        let mut store = secret_store();
        assert_eq!(
            store.store_secret("  ", "value"),
            Err(SecretError::EmptyKey)
        );
        assert_eq!(store.store_secret("key", ""), Err(SecretError::EmptySecret));
        assert_eq!(
            store.store_secret(&"k".repeat(MAX_KEY_CHARS + 1), "value"),
            Err(SecretError::KeyTooLong)
        );
    }

    #[test]
    fn secret_store_debug_never_prints_values() {
        let mut store = secret_store();
        store
            .store_secret("api-key", "sk-live-abc")
            .expect("store secret");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("sk-live-abc"));
    }

    /// Touches the real OS credential store. Ignored by default: CI
    /// environments may have no credential backend, and even locally it
    /// writes (then deletes) a real entry. Run explicitly to verify a
    /// platform backend: `cargo test -p rocky-models -- --ignored`.
    ///
    /// Re-verified 2026-09-06 on a second, independent Windows 11 machine
    /// (`rustc 1.98.1`). The 2026-09-05 note blamed a "vault/session quirk";
    /// that diagnosis was wrong. Root cause: `keyring` 3.x enables no
    /// credential store unless a store feature is requested, and with none
    /// requested `keyring::lib` does `pub use mock as default`.
    /// `MockCredentialBuilder::build` returns a fresh empty credential for
    /// every `Entry::new`, and [`KeyringSecretStore::entry`] builds a new
    /// `Entry` per operation, so `store_secret` wrote into a value that was
    /// dropped and `load_secret` read a different empty one, surfacing as
    /// `NoEntry` -> `Ok(None)`. Not machine-specific, not a vault bug: a
    /// missing Cargo feature. Corroborated by `cargo tree -p keyring`
    /// resolving only `log` + `zeroize`, i.e. no `windows-sys` backend.
    ///
    /// Evidence, same machine, same commit, only the manifest differing:
    /// before enabling `windows-native`, `left: None right:
    /// Some("probe-value")` at the first assertion; after, `1 passed`.
    /// The manifest now requests `windows-native` on Windows and
    /// `apple-native` on macOS, so the backend is dependable on those two.
    ///
    /// Verdict: the *backend* is usable on Windows and macOS; this *test*
    /// stays `#[ignore]`d regardless, because it mutates real OS credential
    /// state and CI has no vault to mutate. The CI-visible guard against a
    /// silent regression to the mock is
    /// `keyring_backend_is_not_the_mock_store` below. Linux is still on the
    /// mock store and must not be trusted; see the manifest and
    /// `docs/plans/DEPENDENCY_REVIEW.md`. The test deletes first so reruns
    /// never stack stale entries.
    #[test]
    #[ignore]
    fn keyring_backend_round_trips_against_the_os() {
        let service = format!("rocky-test-{}", std::process::id());
        let mut store = KeyringSecretStore::new(service).expect("valid test service");
        let _ = store.delete_secret("probe");
        store
            .store_secret("probe", "probe-value")
            .expect("store secret");
        assert_eq!(
            store.load_secret("probe").expect("load secret"),
            Some("probe-value".to_string())
        );
        assert!(store.delete_secret("probe").expect("delete"));
        assert_eq!(store.load_secret("probe").expect("load"), None);
    }

    /// Pins the invariant the 2026-09-06 investigation exposed: on platforms
    /// where a real backend is wired, `keyring`'s compiled-in default must
    /// not be the mock store. The mock accepts writes and then reports
    /// `NoEntry`, so a silent regression here would silently discard every
    /// secret rather than fail. Reads no credential and writes nothing, so
    /// unlike the round-trip test above it is safe to run in CI.
    ///
    /// Gated to Windows and macOS deliberately: Linux has no store feature
    /// requested yet, so the mock *is* the expected default there and this
    /// assertion would be a false alarm.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn keyring_backend_is_not_the_mock_store() {
        let builder = keyring::default::default_credential_builder();
        assert!(
            !builder
                .as_any()
                .is::<keyring::mock::MockCredentialBuilder>(),
            "keyring resolved to the mock credential store; a platform store \
             feature (windows-native / apple-native) is missing from \
             rocky-models/Cargo.toml and every stored secret would be silently \
             discarded"
        );
    }

    #[test]
    fn prompt_builder_frames_sections_deterministically() {
        assert_eq!(
            build_task_prompt(
                "Summarize",
                &["read-only".into()],
                &["line one".into()],
                1024
            ),
            Ok("GOAL\nSummarize\n\nCONSTRAINTS\n- read-only\n\nEVIDENCE\n[1] line one".to_string())
        );
        assert_eq!(
            build_task_prompt("Summarize", &[], &[], 1024),
            Ok("GOAL\nSummarize".to_string())
        );
    }

    #[test]
    fn prompt_builder_rejects_oversized_assemblies() {
        assert_eq!(
            build_task_prompt("goal", &[], &["excerpt".into()], 10),
            Err(ModelError::PromptTooLong)
        );
        assert_eq!(
            build_task_prompt(
                "goal",
                &[],
                &vec!["e".to_string(); MAX_EXCERPTS + 1],
                1_000_000
            ),
            Err(ModelError::TooManyExcerpts)
        );
    }

    fn ollama() -> OllamaProvider {
        OllamaProvider::new("http://localhost:11434", "k2-test", 30_000)
            .expect("valid test provider")
    }

    #[test]
    fn ollama_rejects_non_loopback_and_sloppy_endpoints() {
        for endpoint in [
            "https://example.com",
            "localhost:11434",
            "  ",
            "file:///tmp/x.sock",
            "http://0.0.0.0:11434",
            "http://localhost.evil.com:11434",
        ] {
            assert_eq!(
                OllamaProvider::new(endpoint, "m", 1000).err(),
                Some(ModelError::InvalidRequest),
                "endpoint must be rejected: {endpoint}"
            );
        }
        assert_eq!(
            OllamaProvider::new("http://localhost:11434", "  ", 1000).err(),
            Some(ModelError::InvalidRequest)
        );
        assert_eq!(
            OllamaProvider::new("http://localhost:11434", "m", 0).err(),
            Some(ModelError::InvalidRequest)
        );
        assert!(OllamaProvider::new("http://127.0.0.1:11434", "m", 1000).is_ok());
        assert!(OllamaProvider::new("http://[::1]:11434", "m", 1000).is_ok());
    }

    #[test]
    fn ollama_unreachable_server_is_unavailable_not_panic() {
        let provider =
            OllamaProvider::new("http://127.0.0.1:9", "m", 2_000).expect("valid test provider");
        let request =
            ModelRequest::new("task-1", "hi", 16, Vec::new()).expect("valid test request");
        assert_eq!(
            provider.complete(&request),
            Err(ModelError::ProviderUnavailable)
        );
    }

    #[test]
    fn ollama_maps_text_and_tool_replies() {
        let text = serde_json::json!({
            "model": "m",
            "message": {"role": "assistant", "content": "hello there"},
        });
        let (content, tools) = map_chat_reply(&text).expect("text reply");
        assert_eq!(content, "hello there");
        assert!(tools.is_empty());

        // Object keys sort, so argument order is deterministic no matter
        // how the server serialized the object.
        let calls = serde_json::json!({
            "model": "m",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "filesystem.read",
                        "arguments": {"b": 2, "a": "x"}
                    }
                }]
            }
        });
        let (_, tools) = map_chat_reply(&calls).expect("tool reply");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].tool_id, "filesystem.read");
        assert_eq!(tools[0].arguments, vec!["x".to_string(), "2".to_string()]);
    }

    #[test]
    fn ollama_rejects_malformed_replies() {
        let missing = serde_json::json!({"model": "m"});
        assert_eq!(map_chat_reply(&missing), Err(ModelError::MalformedReply));
        let mistyped = serde_json::json!({
            "model": "m",
            "message": {"role": "assistant", "content": 42}
        });
        assert_eq!(map_chat_reply(&mistyped), Err(ModelError::MalformedReply));
        let unnamed = serde_json::json!({
            "model": "m",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"arguments": {}}}]
            }
        });
        assert_eq!(map_chat_reply(&unnamed), Err(ModelError::MalformedReply));
    }

    #[test]
    fn ollama_provider_reports_local_kind() {
        assert_eq!(ollama().kind(), ProviderKind::Local);
    }
}
