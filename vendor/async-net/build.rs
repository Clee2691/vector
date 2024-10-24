fn main() {
    let cfg = match autocfg::AutoCfg::new() {
        Ok(cfg) => cfg,
        Err(e) => {
            println!(
                "cargo-warning=async-net: failed to detect compiler features: {}",
                e
            );
            return;
        }
    };

    if !cfg.probe_rustc_version(1, 63) {
        autocfg::emit("async_net_no_io_safety");
    }
}
