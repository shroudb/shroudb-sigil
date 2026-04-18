//! Shared test doubles for Sigil debt tests (AUDIT_2026-04-17).
//!
//! RecordingSentry and RecordingChronicle capture PolicyRequests and Events
//! so debt tests can assert what the engine sends to its security
//! capabilities. Kept in `src/` (not `tests/`) so `pub(crate)` internals
//! remain accessible.

use std::sync::{Arc, Mutex};

use shroudb_acl::{AclError, PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyRequest};
use shroudb_chronicle_core::event::Event;
use shroudb_chronicle_core::ops::ChronicleOps;

/// Sentry test double — captures every `PolicyRequest`, always permits.
pub(crate) struct RecordingSentry {
    pub requests: Arc<Mutex<Vec<PolicyRequest>>>,
}

impl RecordingSentry {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> (Arc<dyn PolicyEvaluator>, Arc<Mutex<Vec<PolicyRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let arc = Arc::new(Self {
            requests: requests.clone(),
        });
        (arc as Arc<dyn PolicyEvaluator>, requests)
    }
}

impl PolicyEvaluator for RecordingSentry {
    fn evaluate(
        &self,
        request: &PolicyRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PolicyDecision, AclError>> + Send + '_>,
    > {
        let req = request.clone();
        let requests = self.requests.clone();
        Box::pin(async move {
            requests.lock().unwrap().push(req);
            Ok(PolicyDecision {
                effect: PolicyEffect::Permit,
                matched_policy: Some("test-allow".into()),
                token: None,
                cache_until: None,
            })
        })
    }
}

/// Chronicle test double — captures every `Event`.
pub(crate) struct RecordingChronicle {
    pub events: Arc<Mutex<Vec<Event>>>,
}

impl RecordingChronicle {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> (Arc<dyn ChronicleOps>, Arc<Mutex<Vec<Event>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let arc = Arc::new(Self {
            events: events.clone(),
        });
        (arc as Arc<dyn ChronicleOps>, events)
    }
}

impl ChronicleOps for RecordingChronicle {
    fn record(
        &self,
        event: Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        let events = self.events.clone();
        Box::pin(async move {
            events.lock().unwrap().push(event);
            Ok(())
        })
    }

    fn record_batch(
        &self,
        events: Vec<Event>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        let inner = self.events.clone();
        Box::pin(async move {
            inner.lock().unwrap().extend(events);
            Ok(())
        })
    }
}
