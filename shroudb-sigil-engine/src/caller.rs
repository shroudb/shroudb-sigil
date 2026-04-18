//! Caller identity threaded through engine operations.
//!
//! Every Sigil engine op must know who is calling it — for policy evaluation
//! (`PolicyRequest.principal`) and for audit (`Event.actor` / `Event.tenant_id`).
//! `CallerContext` is the narrow projection of an `AuthContext` that the
//! engine and its `WriteCoordinator` actually need: the caller's actor,
//! tenant, and the roles/claims Sentry uses for ABAC decisions.
//!
//! Dispatch layers (`shroudb-sigil-protocol::dispatch`,
//! `shroudb-sigil-http::router`) convert the connection's `AuthContext` into
//! a `CallerContext` and thread it through every engine method that performs
//! a policy check or emits an audit event.
//!
//! `CallerContext::internal(reason)` is the only legitimate way to issue an
//! unauthenticated internal call (startup schema seeding, background
//! maintenance tasks). The actor is the literal reason string prefixed with
//! `"sigil:internal:"` — never the bare string `"system"`, which made the
//! original audit trail useless for forensics.
//!
//! Construction invariants:
//! - `actor` is never empty.
//! - `internal(reason)` sets `roles = ["sigil:internal"]` and a
//!   `reason` claim so ABAC can still match against a real attribute.

use std::collections::HashMap;

use shroudb_acl::AuthContext;

/// Caller identity threaded from dispatch to engine operations.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// Authenticated actor identity (never empty).
    pub actor: String,
    /// Tenant the caller is operating in (may be empty when a token has no
    /// tenant scoping, e.g. a pre-auth HELLO).
    pub tenant: String,
    /// Roles presented by the caller's token. Sentry uses these for ABAC.
    pub roles: Vec<String>,
    /// Arbitrary claims presented by the caller's token.
    pub claims: HashMap<String, serde_json::Value>,
}

impl CallerContext {
    /// Build an internal caller for ops that don't originate from a
    /// network-authenticated request (startup seeding, background jobs).
    /// The `reason` is carried into the actor string so the audit trail
    /// shows *why* the operation was internal, not just that it was.
    ///
    /// Tenant is `"sigil:internal"` so multi-tenant audit sinks can still
    /// partition internal events without confusing them with tenant traffic.
    pub fn internal(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let mut claims = HashMap::new();
        claims.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.clone()),
        );
        Self {
            actor: format!("sigil:internal:{reason}"),
            tenant: "sigil:internal".to_string(),
            roles: vec!["sigil:internal".to_string()],
            claims,
        }
    }

    /// Build a caller context from a fully-authenticated `AuthContext`.
    /// Roles are derived from the token's namespace grants (one role per
    /// granted namespace) so Sentry has a non-empty attribute set.
    pub fn from_auth(auth: &AuthContext) -> Self {
        let roles: Vec<String> = if auth.is_platform {
            vec!["platform".to_string()]
        } else {
            auth.grants
                .iter()
                .map(|g| format!("ns:{}", g.namespace))
                .collect()
        };
        let mut claims = HashMap::new();
        claims.insert(
            "is_platform".to_string(),
            serde_json::Value::Bool(auth.is_platform),
        );
        let actor = if auth.actor.is_empty() {
            "anonymous".to_string()
        } else {
            auth.actor.clone()
        };
        Self {
            actor,
            tenant: auth.tenant.clone(),
            roles,
            claims,
        }
    }

    /// Build a caller context for an anonymous (unauthenticated) request.
    /// Actor is the literal `"anonymous"` — never empty, never the bare
    /// `"system"`.
    pub fn anonymous() -> Self {
        let mut claims = HashMap::new();
        claims.insert("is_platform".to_string(), serde_json::Value::Bool(false));
        Self {
            actor: "anonymous".to_string(),
            tenant: String::new(),
            roles: vec!["anonymous".to_string()],
            claims,
        }
    }

    /// Return the tenant id as an `Option<String>`: `None` when the tenant
    /// string is empty, `Some(..)` otherwise. Used when populating
    /// `Event.tenant_id` so audit records carry `null` rather than an empty
    /// string for unscoped tokens.
    pub fn tenant_opt(&self) -> Option<String> {
        if self.tenant.is_empty() {
            None
        } else {
            Some(self.tenant.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_acl::{Grant, Scope};

    #[test]
    fn internal_carries_reason_in_actor_and_claims() {
        let ctx = CallerContext::internal("startup-seed");
        assert_eq!(ctx.actor, "sigil:internal:startup-seed");
        assert_eq!(ctx.roles, vec!["sigil:internal".to_string()]);
        assert_eq!(
            ctx.claims.get("reason"),
            Some(&serde_json::Value::String("startup-seed".into()))
        );
        assert_ne!(ctx.actor, "system", "actor must never be literal 'system'");
    }

    #[test]
    fn anonymous_uses_literal_anonymous_not_empty() {
        let ctx = CallerContext::anonymous();
        assert_eq!(ctx.actor, "anonymous");
        assert!(!ctx.actor.is_empty());
    }

    #[test]
    fn from_auth_platform_carries_platform_role() {
        let auth = AuthContext::platform("tenant-a", "admin");
        let ctx = CallerContext::from_auth(&auth);
        assert_eq!(ctx.actor, "admin");
        assert_eq!(ctx.tenant, "tenant-a");
        assert!(ctx.roles.contains(&"platform".to_string()));
    }

    #[test]
    fn from_auth_tenant_carries_ns_grants_as_roles() {
        let auth = AuthContext::tenant(
            "t1",
            "bob",
            vec![Grant {
                namespace: "sigil.users".into(),
                scopes: vec![Scope::Read],
            }],
            None,
        );
        let ctx = CallerContext::from_auth(&auth);
        assert_eq!(ctx.actor, "bob");
        assert!(ctx.roles.contains(&"ns:sigil.users".to_string()));
    }

    #[test]
    fn tenant_opt_returns_some_for_internal() {
        let ctx = CallerContext::internal("job");
        assert_eq!(ctx.tenant_opt(), Some("sigil:internal".into()));
        let auth = AuthContext::platform("tenant-x", "admin");
        let ctx = CallerContext::from_auth(&auth);
        assert_eq!(ctx.tenant_opt(), Some("tenant-x".into()));
    }

    #[test]
    fn tenant_opt_returns_none_for_empty_tenant() {
        let ctx = CallerContext::anonymous();
        assert!(ctx.tenant_opt().is_none());
    }
}
