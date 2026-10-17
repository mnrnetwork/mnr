//! Whose load an upstream call is: the Stage 1 gate (plan §9) reads the
//! owned node's share of *external* work units, so load caused by our own
//! tokens (`internal_tokens` in the config) and by the relay's own
//! housekeeping (the header-chain sync) is counted separately.
//!
//! The flag rides a task-local set around the work it covers: ingress scopes
//! each request, `main` scopes the chain sync. Every `.await` inside the scope,
//! `join_all` fan-outs included, sees it; a `tokio::spawn` does not, so a
//! spawn that does work on behalf of a request captures [`internal`] first and
//! re-scopes ([`scope`]). Outside any scope a call counts as external: a future
//! spawn that forgets to re-scope shows up as external load, never hides it.

use std::future::Future;

tokio::task_local! {
    static INTERNAL: bool;
}

/// True when the current task's upstream load is ours (an internal token or
/// relay housekeeping); false outside any scope.
pub fn internal() -> bool {
    INTERNAL.try_with(|v| *v).unwrap_or(false)
}

/// Run `fut` with its upstream load attributed as internal or external.
pub fn scope<F: Future>(internal: bool, fut: F) -> impl Future<Output = F::Output> {
    INTERNAL.scope(internal, fut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inside_a_scope_is_what_it_says_and_outside_is_external() {
        assert!(!internal());
        assert!(scope(true, async { internal() }).await);
        assert!(!scope(false, async { internal() }).await);
        assert!(!internal());
    }

    #[tokio::test]
    async fn a_spawn_from_a_scope_does_not_inherit_it_unless_re_scoped() {
        let lost = scope(true, async {
            tokio::spawn(async { internal() }).await.unwrap()
        })
        .await;
        assert!(!lost, "task-locals do not cross tokio::spawn");
        let kept = scope(true, async {
            let flag = internal();
            tokio::spawn(scope(flag, async { internal() }))
                .await
                .unwrap()
        })
        .await;
        assert!(kept);
    }
}
