//! The command's name. Everything the CLI prints says `sprott`; `sc` and
//! `safeclaw` are aliases of the same binary and keep working.
//!
//! Installs before 1.5 put the binary at `~/.local/bin/sc` only, and `sc
//! upgrade` replaces that file in place, so an upgraded machine would have no
//! `sprott` while every hint names it. [`ensure_canonical_beside`] closes the
//! gap: run as `sc` or `safeclaw` with nothing called `sprott` next to it, the
//! binary adds `sprott` there as a relative symlink to itself. An older `sc
//! upgrade` runs the new binary's `version` right after the swap, so the link
//! appears during the upgrade.

use std::path::{Path, PathBuf};

/// The canonical command name.
pub const CANONICAL: &str = "sprott";
/// Names the same binary also answers to.
pub const ALIASES: [&str; 2] = ["sc", "safeclaw"];

/// Best effort and silent: an unwritable directory or a non-Unix host leaves
/// things as they are.
pub fn ensure_canonical_beside() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = ensure_canonical_at(&exe);
    }
}

/// Creates `<dir of exe>/sprott -> <exe file name>` when `exe` is named after
/// an alias and nothing (not even a dangling link) is called `sprott` beside
/// it. Returns the link it created.
fn ensure_canonical_at(exe: &Path) -> std::io::Result<Option<PathBuf>> {
    let Some(name) = exe.file_name().and_then(|n| n.to_str()) else {
        return Ok(None);
    };
    if !ALIASES.contains(&name) {
        return Ok(None);
    }
    let Some(dir) = exe.parent() else {
        return Ok(None);
    };
    let link = dir.join(CANONICAL);
    if std::fs::symlink_metadata(&link).is_ok() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(name, &link)?;
        Ok(Some(link))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn an_alias_only_install_gains_sprott_once() {
        let dir = tempfile::tempdir().unwrap();
        let sc = dir.path().join("sc");
        fs::write(&sc, b"binary").unwrap();

        let link = ensure_canonical_at(&sc).unwrap().expect("link created");
        assert_eq!(link, dir.path().join("sprott"));
        assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("sc"));
        assert_eq!(fs::read(&link).unwrap(), b"binary");
        assert!(ensure_canonical_at(&sc).unwrap().is_none(), "second run is a no-op");
    }

    #[test]
    fn leaves_an_existing_sprott_and_other_names_alone() {
        let dir = tempfile::tempdir().unwrap();
        let safeclaw = dir.path().join("safeclaw");
        fs::write(&safeclaw, b"old").unwrap();
        let sprott = dir.path().join("sprott");
        fs::write(&sprott, b"other").unwrap();
        assert!(ensure_canonical_at(&safeclaw).unwrap().is_none());
        assert_eq!(fs::read(&sprott).unwrap(), b"other");

        let dangling = tempfile::tempdir().unwrap();
        let sc = dangling.path().join("sc");
        fs::write(&sc, b"binary").unwrap();
        std::os::unix::fs::symlink("missing", dangling.path().join("sprott")).unwrap();
        assert!(ensure_canonical_at(&sc).unwrap().is_none(), "a dangling link counts");

        let elsewhere = tempfile::tempdir().unwrap();
        let canonical = elsewhere.path().join("sprott");
        fs::write(&canonical, b"binary").unwrap();
        assert!(ensure_canonical_at(&canonical).unwrap().is_none());
        let test_binary = elsewhere.path().join("safeclaw-0123abcd");
        fs::write(&test_binary, b"binary").unwrap();
        assert!(ensure_canonical_at(&test_binary).unwrap().is_none());
    }
}
