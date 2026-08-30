pub mod dockerfile;
pub mod nginx;
pub mod sshd;

use std::path::Path;

/// Which parser applies to a file, decided from its name/path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Sshd,
    Nginx,
    Dockerfile,
}

/// Guess the config type from a file's name. Returns `None` for files we
/// don't know how to audit (the caller should skip or warn on these).
#[must_use]
pub fn detect(path: &Path) -> Option<FileKind> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if name.contains("sshd_config") {
        return Some(FileKind::Sshd);
    }
    if name == "dockerfile"
        || name.starts_with("dockerfile.")
        || name.ends_with(".dockerfile")
        || name.contains("dockerfile")
    {
        return Some(FileKind::Dockerfile);
    }
    if ext == "conf" || name == "nginx.conf" || name.contains("nginx") {
        return Some(FileKind::Nginx);
    }
    None
}
