#[cfg(not(windows))]
fn main() {
    eprintln!("gamepath-service is available only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    server::run()
}

#[cfg(windows)]
mod bypass_routes;
#[cfg(windows)]
mod engine_process;
#[cfg(windows)]
mod l2tp;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod server;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod slot;
#[cfg(windows)]
mod validate;

#[cfg(windows)]
fn log_event(message: &str) {
    gamepath_engine::log_info!("{message}");
}
