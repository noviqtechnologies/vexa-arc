fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Ensure a consistent 8 MiB stack across Windows (MSVC/MinGW) and Linux musl
    // (matching macOS/Linux glibc defaults) so debug and release CLI binaries never
    // hit stack overflow during clap argument parsing or deep command dispatch.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    match (target_os.as_str(), target_env.as_str()) {
        ("windows", "msvc") => {
            println!("cargo:rustc-link-arg=/STACK:8388608");
        }
        ("windows", "gnu") => {
            println!("cargo:rustc-link-arg=-Wl,--stack,8388608");
        }
        ("linux", "musl") => {
            println!("cargo:rustc-link-arg=-Wl,-z,stack-size=8388608");
        }
        _ => {}
    }
}
