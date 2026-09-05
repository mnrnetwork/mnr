//! Records the git commit the binary was built from, for the self-reported
//! `relay` block in `/upstreams.json` and the `Mnr-Relay` header. This is
//! information, not proof: a modified build can report anything.
use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=MNR_GIT_SHA={sha}");
    println!(
        "cargo:rustc-env=MNR_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
}
