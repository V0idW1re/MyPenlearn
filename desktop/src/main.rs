#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Force software rendering so the app starts in VMs without GPU acceleration.
    // These must be set before WebKitGTK initialises (i.e. before run()).
    #[cfg(target_os = "linux")]
    {
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "1");
    }

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .init();
    penligent_local_lib::run();
}
