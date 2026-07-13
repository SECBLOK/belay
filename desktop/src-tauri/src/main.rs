#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(all(feature = "tauri", feature = "tokio"))]
    belay_desktop_lib::run();
}
