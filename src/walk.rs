//! Filesystem traversal. Skip .git, ignored names, binaries, and huge files.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use walkdir::WalkDir;

use crate::config::Config;

const BINARY_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "pdf", "zip", "gz", "tgz", "tar", "7z",
    "exe", "dll", "so", "dylib", "wasm", "woff", "woff2", "ttf", "mp3", "mp4", "class", "o", "a",
    "rlib", "rmeta", "pdb", "bin",
];

pub struct FileContent {
    pub relative: String,
    pub text: String,
}

pub fn collect_files(root: &Path, cfg: &Config) -> Vec<FileContent> {
    let mut out = Vec::new();
    if root.is_file() {
        if let Some(mut item) = read_one(root, root.parent().unwrap_or(root), cfg) {
            item.relative = root.to_string_lossy().replace('\\', "/");
            out.push(item);
        }
        return out;
    }

    let walker = WalkDir::new(root).follow_links(false).into_iter();
    for entry in walker.filter_entry(|e| !is_ignored(e.path(), root, cfg)) {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(item) = read_one(entry.path(), root, cfg) {
            out.push(item);
        }
    }
    out
}

fn is_ignored(path: &Path, root: &Path, cfg: &Config) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    for component in rel.components() {
        let name = component.as_os_str().to_string_lossy();
        if cfg.ignore_paths.iter().any(|p| p == name.as_ref()) {
            return true;
        }
    }
    let joined = rel.to_string_lossy().replace('\\', "/");
    cfg.ignore_paths.iter().any(|p| joined.contains(p))
}

fn read_one(path: &Path, root: &Path, cfg: &Config) -> Option<FileContent> {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if BINARY_EXT.iter().any(|b| b.eq_ignore_ascii_case(ext)) {
            return None;
        }
    }
    let meta = path.metadata().ok()?;
    if meta.len() > cfg.max_file_bytes {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    if is_probably_binary(&buf) {
        return None;
    }
    let text = String::from_utf8(buf).ok()?;
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    Some(FileContent { relative, text })
}

pub fn is_probably_binary(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return true;
    }
    std::str::from_utf8(bytes).is_err()
}

pub fn text_from_bytes(bytes: &[u8], cfg: &Config) -> Option<String> {
    if bytes.len() as u64 > cfg.max_file_bytes {
        return None;
    }
    if is_probably_binary(bytes) {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nul_bytes_are_binary() {
        assert!(is_probably_binary(b"hello\0world"));
        assert!(!is_probably_binary(b"hello world"));
    }
}
