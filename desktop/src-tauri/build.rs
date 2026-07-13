fn main() {
    // Only call tauri_build when the `tauri-build` build-dependency is available.
    // When building with --no-default-features (e.g. for lib unit tests),
    // tauri-build is excluded and we skip this.
    #[cfg(feature = "tauri-build")]
    tauri_build::build()
}
