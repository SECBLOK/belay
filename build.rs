fn main() {
    // Mirror the daemon's `fw` cfg (see daemon/build.rs). The root binary's
    // firewall-feature code calls into `belayd` APIs that only exist on
    // Linux (rustables-backed), so the same call sites are gated on `fw` and
    // degrade cleanly on macOS/Windows even though the `firewall` feature stays
    // in the default set.
    println!("cargo::rustc-check-cfg=cfg(fw)");
    if std::env::var_os("CARGO_FEATURE_FIREWALL").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        println!("cargo::rustc-cfg=fw");
    }
}
