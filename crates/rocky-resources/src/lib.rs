//! Pure, inexpensive resource-admission decisions.

/// Coarse runtime mode used to apply backpressure before work is spawned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceMode {
    Idle,
    Normal,
    Constrained,
    Critical,
}

/// Sanitized metrics supplied by a platform-specific sampler at the application edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceSnapshot {
    pub cpu_percent: u8,
    pub memory_percent: u8,
    pub on_battery: bool,
}

impl ResourceSnapshot {
    /// Classifies resource pressure without sampling or polling itself.
    pub fn mode(self) -> ResourceMode {
        if self.cpu_percent >= 95 || self.memory_percent >= 95 {
            ResourceMode::Critical
        } else if self.cpu_percent >= 80 || self.memory_percent >= 80 || self.on_battery {
            ResourceMode::Constrained
        } else if self.cpu_percent == 0 && self.memory_percent == 0 {
            ResourceMode::Idle
        } else {
            ResourceMode::Normal
        }
    }

    /// Reports the classified mode only when it differs from the previous
    /// one. Samplers call this per sample; UI `resource.mode_changed` events
    /// originate here, so flapping-free emission is a property of the helper
    /// rather than of every future sampler.
    pub fn mode_change(self, previous: ResourceMode) -> Option<ResourceMode> {
        let current = self.mode();
        (current != previous).then_some(current)
    }
}

/// The outcome of asking to start a bounded unit of work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Admit,
    Queue,
    Reject,
}

/// Computes admission without owning worker threads or creating background loops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceGovernor {
    max_normal_workers: usize,
}

impl ResourceGovernor {
    pub fn new(max_normal_workers: usize) -> Self {
        Self { max_normal_workers }
    }

    pub fn admit(self, mode: ResourceMode, active_workers: usize) -> Admission {
        match mode {
            ResourceMode::Critical => Admission::Reject,
            ResourceMode::Idle => Admission::Queue,
            ResourceMode::Constrained if active_workers >= 1 => Admission::Queue,
            ResourceMode::Normal if active_workers >= self.max_normal_workers => Admission::Queue,
            ResourceMode::Constrained | ResourceMode::Normal => Admission::Admit,
        }
    }
}

/// Single-shot OS resource sampler.
///
/// Reads CPU and memory counters once per call through sysinfo: no threads,
/// no polling loops, no background work. Polling cadence stays the caller's
/// decision (and should be seconds, not milliseconds — CPU readings are
/// deltas between refreshes, so rapid polling measures nothing real).
/// Battery state is conservatively reported as plugged in: throttling the
/// machine on unknown power state would punish desktops for a laptop signal.
pub struct SystemSampler {
    system: sysinfo::System,
}

impl SystemSampler {
    pub fn new() -> Self {
        let mut system = sysinfo::System::new_all();
        system.refresh_all();
        Self { system }
    }

    pub fn sample(&mut self) -> ResourceSnapshot {
        self.system.refresh_cpu_all();
        self.system.refresh_memory();
        // Ratios only: memory units differ across sysinfo versions, but the
        // quotient is unit-free by construction.
        let memory_percent = match self.system.total_memory() {
            0 => 0,
            total => ((self.system.used_memory() as f64 / total as f64) * 100.0) as u8,
        };
        ResourceSnapshot {
            cpu_percent: self.system.global_cpu_usage().clamp(0.0, 100.0).round() as u8,
            memory_percent: memory_percent.min(100),
            on_battery: false,
        }
    }
}

impl Default for SystemSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_pressure_rejects_new_work() {
        let governor = ResourceGovernor::new(3);
        assert_eq!(governor.admit(ResourceMode::Critical, 0), Admission::Reject);
    }

    #[test]
    fn constrained_mode_caps_parallelism_at_one_worker() {
        let governor = ResourceGovernor::new(3);
        assert_eq!(
            governor.admit(ResourceMode::Constrained, 0),
            Admission::Admit
        );
        assert_eq!(
            governor.admit(ResourceMode::Constrained, 1),
            Admission::Queue
        );
    }

    fn snapshot(cpu: u8, memory: u8) -> ResourceSnapshot {
        ResourceSnapshot {
            cpu_percent: cpu,
            memory_percent: memory,
            on_battery: false,
        }
    }

    #[test]
    fn mode_changes_report_only_transitions() {
        assert_eq!(snapshot(10, 10).mode_change(ResourceMode::Normal), None);
        assert_eq!(
            snapshot(96, 10).mode_change(ResourceMode::Normal),
            Some(ResourceMode::Critical)
        );
        assert_eq!(snapshot(96, 10).mode_change(ResourceMode::Critical), None);
    }

    #[test]
    fn system_sampler_reports_bounded_sanitary_values() {
        // Exact readings depend on the host, so the test pins the contract:
        // every field lands in range and classifies without panicking.
        let mut sampler = SystemSampler::new();
        for _ in 0..3 {
            let sample = sampler.sample();
            assert!(sample.cpu_percent <= 100);
            assert!(sample.memory_percent <= 100);
            assert!(!sample.on_battery);
            let _ = sample.mode();
        }
    }
}
