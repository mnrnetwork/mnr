//! Regenerate `docs/method-policy.md` from the code:
//!
//! ```sh
//! cargo run -p mnr-core --example render_policy > docs/method-policy.md
//! ```

fn main() {
    print!("{}", mnr_core::policy::render_markdown());
}
