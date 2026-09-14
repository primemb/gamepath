//! What the UI is told about a running session.
//!
//! The workers publish their counters and the scheduler its pick in separate
//! places, so this is where they are joined into one snapshot - including the
//! reconciliation that keeps a route from being reported as carrying traffic
//! while the dispatcher is skipping it.

use super::WireGuardSessionManager;
use super::health::selected_paths;
use super::worker::PATH_QUEUE_DEPTH;
use gamepath_engine::relay_path::SessionMode;
use gamepath_engine::uplink::UplinkState;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

impl WireGuardSessionManager {
    pub(crate) fn status(&self) -> Value {
        let Some(session) = &self.active else {
            return json!({ "state": "idle", "paths": [] });
        };
        let mut paths = session.paths.lock().unwrap().clone();
        let scheduler_metrics = session.scheduler_metrics.lock().unwrap().clone();
        // The workers own these two structures separately, so the live loss
        // estimate is joined onto the path status here rather than written on
        // the hot path under a second lock.
        for (path, metric) in paths.iter_mut().zip(scheduler_metrics.iter()) {
            path.loss_percent = metric.loss_ratio * 100.0;
        }
        let decision = session.decision_mask.load(Ordering::Acquire);
        let healthy = session.telemetry.healthy_mask.load(Ordering::Acquire);
        // What the dispatcher will actually use. Reporting the raw pick would
        // show a route as carrying traffic while it is being skipped.
        let effective = selected_paths(decision, healthy);
        let selected_routes = paths
            .iter()
            .enumerate()
            .filter(|(index, _)| effective & 1_u64.checked_shl(*index as u32).unwrap_or(0) != 0)
            .map(|(_, path)| path.route)
            .collect::<Vec<_>>();
        let degraded_routes = paths
            .iter()
            .filter(|path| !path.reachable)
            .map(|path| path.route)
            .collect::<Vec<_>>();
        let path_worker_iterations = session
            .telemetry
            .iterations
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        let state = if paths.iter().any(|path| path.reachable) {
            "connected"
        } else {
            "connecting"
        };
        json!({
            "state": state,
            "mode": session.mode.as_str(),
            "sessionId": session.session_id.to_string(),
            "startedAt": session.started_at,
            "paths": paths,
            "skippedRoutes": session.skipped_routes,
            "strategy": match session.mode {
                SessionMode::Relay => session.strategy.as_str(),
                // One path cannot be scheduled between, so nothing is chosen.
                SessionMode::Direct => "single-path",
            },
            "selectedRoutes": selected_routes,
            // Routes the session started or carried on without. Present so the
            // UI can say a path is down without implying the session is.
            "degradedRoutes": degraded_routes,
            "schedulerMetrics": scheduler_metrics,
            "pathWorkerIterations": path_worker_iterations,
            "queueDepth": session
                .telemetry
                .queue_depth
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            "droppedPackets": session
                .telemetry
                .dropped
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            "queuePeak": session
                .telemetry
                .queue_peak
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            "dropReasons": {
                "queueFull": session.telemetry.queue_full_dropped.iter()
                    .map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>(),
                "stale": session.telemetry.stale_dropped.iter()
                    .map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>(),
                "inboundFull": session.telemetry.inbound_dropped.iter()
                    .map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>(),
            },
            "workerGapPeakMs": session.telemetry.worker_gap_peak_ms.iter()
                .map(|value| value.load(Ordering::Relaxed)).collect::<Vec<_>>(),
            "queueCapacity": PATH_QUEUE_DEPTH,
            "effectiveMtu": session.effective_mtu.mtu,
            "transportOverhead": session.effective_mtu.overhead,
            "uplink": match session.telemetry.uplink.state() {
                UplinkState::Up => "up",
                UplinkState::Down => "down",
                UplinkState::Unknown => "unknown",
            },
            "highResolutionTimer": session.timer.active(),
        })
    }
}
