use alloc::string::String;
use alloc::vec::Vec;
use crate::layout::DEFAULT_PROCESS_ROOT;

fn normalize_absolute(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            let _ = stack.pop();
            continue;
        }
        stack.push(part);
    }

    if stack.is_empty() {
        return String::from("/");
    }

    let mut out = String::new();
    for part in stack {
        out.push('/');
        out.push_str(part);
    }
    out
}

fn normalize_root(root_dir: &str) -> String {
    let candidate = if root_dir.is_empty() {
        String::from(DEFAULT_PROCESS_ROOT)
    } else if root_dir.starts_with('/') {
        String::from(root_dir)
    } else {
        let mut prefixed = String::from("/");
        prefixed.push_str(root_dir);
        prefixed
    };

    normalize_absolute(&candidate)
}

fn remap_absolute_into_root(abs_path: &str, root_dir: &str) -> String {
    if root_dir == "/" {
        return String::from(abs_path);
    }

    if abs_path == "/" {
        return String::from(root_dir);
    }

    if abs_path == root_dir {
        return String::from(abs_path);
    }

    let mut root_prefix = String::from(root_dir);
    root_prefix.push('/');
    if abs_path.starts_with(&root_prefix) {
        return String::from(abs_path);
    }

    let mut out = String::with_capacity(root_dir.len() + abs_path.len());
    out.push_str(root_dir);
    out.push_str(abs_path);
    normalize_absolute(&out)
}

fn normalize_cwd_in_root(cwd: &str, root_dir: &str) -> String {
    let normalized = if cwd.is_empty() {
        String::from(root_dir)
    } else if cwd.starts_with('/') {
        normalize_absolute(cwd)
    } else {
        let mut base = String::from(root_dir);
        if !base.ends_with('/') {
            base.push('/');
        }
        base.push_str(cwd);
        normalize_absolute(&base)
    };

    remap_absolute_into_root(&normalized, root_dir)
}

pub fn resolve_path(raw_path: &str, root_dir: &str, cwd: &str) -> String {
    if raw_path.is_empty() {
        return normalize_cwd_in_root(cwd, &normalize_root(root_dir));
    }

    let root = normalize_root(root_dir);

    if raw_path.starts_with('/') {
        let abs = normalize_absolute(raw_path);
        return remap_absolute_into_root(&abs, &root);
    }

    let cwd_abs = normalize_cwd_in_root(cwd, &root);
    let mut joined = String::from(&cwd_abs);
    if !joined.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(raw_path);

    let abs = normalize_absolute(&joined);
    remap_absolute_into_root(&abs, &root)
}
