use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".lazyvpn-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn readers_keep_complete_old_snapshot_and_new_file_is_private() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        fs::write(&path, b"old snapshot").unwrap();
        let mut reader = File::open(&path).unwrap();
        write(&path, b"new snapshot").unwrap();
        let mut old = String::new();
        reader.read_to_string(&mut old).unwrap();
        assert_eq!(old, "old snapshot");
        assert_eq!(fs::read(&path).unwrap(), b"new snapshot");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn replaces_symlink_without_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let path = temp.path().join("state");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, &path).unwrap();
        write(&path, b"snapshot").unwrap();
        assert_eq!(fs::read(target).unwrap(), b"untouched");
        assert!(!fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
}
