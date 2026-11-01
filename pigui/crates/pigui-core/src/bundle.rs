use std::env;
use std::path::{Path, PathBuf};

/// Return the enclosing `.app` bundle for an executable path.
pub fn bundle_root_from_path(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| candidate.extension().and_then(|value| value.to_str()) == Some("app"))
        .map(Path::to_path_buf)
}

/// Return the app bundle containing the current executable, if any.
pub fn current_bundle_root() -> Option<PathBuf> {
    env::current_exe()
        .ok()
        .and_then(|path| bundle_root_from_path(&path))
}

pub fn is_bundled() -> bool {
    current_bundle_root().is_some()
}

pub fn contents_dir() -> Option<PathBuf> {
    current_bundle_root().map(|root| root.join("Contents"))
}

pub fn macos_dir() -> Option<PathBuf> {
    contents_dir().map(|contents| contents.join("MacOS"))
}

pub fn resources_dir() -> Option<PathBuf> {
    contents_dir().map(|contents| contents.join("Resources"))
}

pub fn snort_binary() -> Option<PathBuf> {
    let path = macos_dir()?.join("snort");
    path.is_file().then_some(path)
}

pub fn snort_lua_dir() -> Option<PathBuf> {
    let path = resources_dir()?.join("snort/lua");
    path.is_dir().then_some(path)
}

pub fn snort_config() -> Option<PathBuf> {
    let resources = resources_dir()?;
    let generated = resources.join("snort/etc/snort.lua");
    if generated.is_file() {
        return Some(generated);
    }
    let source = resources.join("snort/lua/snort.lua");
    source.is_file().then_some(source)
}

/// Production home directory for an app-bundle launch.
pub fn production_home() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("PIGUI")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_app_bundle_from_executable() {
        let path = Path::new("/Applications/PIGUI.app/Contents/MacOS/PIGUI");
        assert_eq!(
            bundle_root_from_path(path),
            Some(PathBuf::from("/Applications/PIGUI.app"))
        );
    }

    #[test]
    fn ignores_development_binaries() {
        let path = Path::new("/Users/dev/pigui/target/debug/pigui-daemon");
        assert_eq!(bundle_root_from_path(path), None);
    }
}
