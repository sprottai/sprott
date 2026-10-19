//! The product's names on disk, on the wire and in release assets, one
//! constant each (2.0). The only code that still spells a pre-2.0 name is
//! `cli::migrate`, which moves the old directory and service unit once, and the
//! proxy's refusal of a pre-2.0 phantom (`proxy::resolver::old_phantom`).

use std::path::{Path, PathBuf};

/// The data directory under `$HOME`: config, identities, vault state, logs.
pub const DATA_DIR: &str = ".sprott";

/// The phantom prefix: `__sprott__<conn>__` or `__sprott__<conn>__<role>__`.
pub const PHANTOM_PREFIX: &str = "__sprott__";

/// The systemd user unit `sprott up` writes on Linux.
pub const SYSTEMD_UNIT: &str = "sprott.service";

/// The launchd label `sprott up` uses on macOS; the plist is `<label>.plist`.
pub const LAUNCHD_LABEL: &str = "ai.sprott.daemon";

/// Release assets are `<prefix>-<os>-<arch>`.
pub const ASSET_PREFIX: &str = "sprott";

/// The User-Agent of every outbound HTTP client.
pub const USER_AGENT: &str = concat!("sprott/", env!("CARGO_PKG_VERSION"));

/// `<home>/.sprott`.
pub fn data_dir_in(home: &Path) -> PathBuf {
    home.join(DATA_DIR)
}

/// `~/.sprott`, or `None` when there is no home directory.
pub fn data_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| data_dir_in(&h))
}
