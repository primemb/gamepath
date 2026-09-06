use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterCapability {
    pub library_available: bool,
    pub library_loaded: bool,
    pub driver_version: Option<String>,
    pub message: String,
}

#[cfg(windows)]
pub fn inspect_library(path: &Path) -> AdapterCapability {
    if !path.is_file() {
        return AdapterCapability {
            library_available: false,
            library_loaded: false,
            driver_version: None,
            message: "wintun.dll was not found".into(),
        };
    }

    // SAFETY: GamePath ships the hash-verified, Authenticode-signed Wintun DLL
    // beside the application and passes its absolute path here.
    match unsafe { wintun::load_from_path(path) } {
        Ok(library) => {
            let driver_version = wintun::get_running_driver_version(&library)
                .ok()
                .map(|version| version.to_string());
            AdapterCapability {
                library_available: true,
                library_loaded: true,
                driver_version,
                message: "Signed Wintun library is ready".into(),
            }
        }
        Err(error) => AdapterCapability {
            library_available: true,
            library_loaded: false,
            driver_version: None,
            message: format!("Wintun could not be loaded: {error}"),
        },
    }
}

#[cfg(not(windows))]
pub fn inspect_library(path: &Path) -> AdapterCapability {
    AdapterCapability {
        library_available: path.is_file(),
        library_loaded: false,
        driver_version: None,
        message: "Wintun is supported only on Windows".into(),
    }
}
