use anyhow::{bail, Context};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};

pub struct Instance {
    _lock: File,
    socket: PathBuf,
    task: Option<tokio::task::JoinHandle<()>>,
    pid_file: Option<PathBuf>,
}

impl Instance {
    pub fn runtime_dir() -> anyhow::Result<PathBuf> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", uid())));
        runtime_dir_in(&base, Path::new("/tmp"))
    }

    pub fn acquire(dir: &Path) -> anyhow::Result<Option<Self>> {
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).context("Cannot create LazyVPN runtime directory"),
        }
        let metadata = fs::symlink_metadata(dir)?;
        if !metadata.is_dir() || metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
            bail!("LazyVPN runtime directory must be owned by you with mode 0700");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join("instance.lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            bail!("Unsafe LazyVPN lock file");
        }
        match lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let socket = dir.join("activate.sock");
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(Some(Self {
            _lock: lock,
            socket,
            task: None,
            pid_file: None,
        }))
    }

    pub fn publish_pid(&mut self, config: &Path) -> anyhow::Result<()> {
        let pid_file = config.join(".pid");
        let pid = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let state_pid = fs::read(config.join(".connection_state"))
            .ok()
            .and_then(|s| serde_json::from_slice::<serde_json::Value>(&s).ok())
            .and_then(|s| s["pid"].as_u64())
            .and_then(|p| u32::try_from(p).ok());
        if pid.into_iter().chain(state_pid).any(is_legacy_instance) {
            bail!("An older LazyVPN instance is still running; close its interface once before reopening");
        }
        fs::create_dir_all(config)?;
        crate::utils::atomic_file::write(&pid_file, std::process::id().to_string().as_bytes())?;
        self.pid_file = Some(pid_file);
        Ok(())
    }

    pub fn serve_activation(&mut self) -> anyhow::Result<()> {
        let listener = UnixListener::bind(&self.socket)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(0o600))?;
        self.task = Some(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = timeout(Duration::from_secs(2), handle_activation(stream)).await;
            }
        }));
        Ok(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = fs::remove_file(&self.socket);
        if let Some(path) = &self.pid_file {
            let _ = fs::remove_file(path);
        }
        // Keep the inode: unlinking a lock file lets new callers lock a different file.
    }
}

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn runtime_dir_in(base: &Path, fallback: &Path) -> anyhow::Result<PathBuf> {
    match fs::metadata(base) {
        Ok(metadata) if metadata.is_dir() => Ok(base.join("monarch-lazyvpn")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(fallback.join(format!("monarch-lazyvpn-{}", uid())))
        }
        Err(error) => Err(error).context("Cannot inspect session runtime directory"),
        Ok(_) => bail!("Session runtime path is not a directory"),
    }
}

pub fn owner_running() -> anyhow::Result<bool> {
    let path = Instance::runtime_dir()?.join("instance.lock");
    let lock = match OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid() || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0 {
        bail!("Unsafe LazyVPN lock file");
    }
    match lock.try_lock_exclusive() {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn is_legacy_instance(pid: u32) -> bool {
    if pid == std::process::id() {
        return false;
    }
    let proc = PathBuf::from(format!("/proc/{pid}"));
    if !fs::metadata(&proc).is_ok_and(|m| m.uid() == uid()) {
        return false;
    }
    fs::read_link(proc.join("exe"))
        .ok()
        .and_then(|p| {
            p.file_name().map(|s| {
                s.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_owned()
            })
        })
        .is_some_and(|s| matches!(s.as_str(), "monarch-lazyvpn" | "monarch-lazyvpn-gui"))
}

pub async fn open(gui: bool, preview: bool) -> anyhow::Result<Option<Instance>> {
    let mut dir = Instance::runtime_dir()?;
    if preview {
        let mut name = dir.file_name().unwrap().to_os_string();
        name.push("-preview");
        dir.set_file_name(name);
    }
    for _ in 0..20 {
        if let Some(instance) = Instance::acquire(&dir)? {
            return Ok(Some(instance));
        }
        if !gui {
            bail!("LazyVPN is already running; use its interface to change the VPN");
        }
        match timeout(Duration::from_secs(3), activate(&dir.join("activate.sock"))).await {
            Ok(Ok(true)) => return Ok(None),
            Ok(Ok(false)) => bail!("LazyVPN is already running, but its window could not be focused; return to the existing window"),
            Ok(Err(e)) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) => {
                sleep(Duration::from_millis(50)).await;
            }
            _ => bail!("LazyVPN is already running but did not respond to activation"),
        }
    }
    bail!("LazyVPN is busy starting or running a CLI command; try again shortly")
}

async fn activate(socket: &Path) -> io::Result<bool> {
    let mut stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != uid() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    stream.write_all(b"activate\n").await?;
    let mut reply = [0; 3];
    stream.read_exact(&mut reply).await?;
    Ok(&reply == b"ok\n")
}

async fn handle_activation(mut stream: UnixStream) -> anyhow::Result<()> {
    if stream.peer_cred()?.uid() != uid() {
        bail!("Activation peer has a different UID");
    }
    let mut request = [0; 9];
    stream.read_exact(&mut request).await?;
    if &request != b"activate\n" {
        bail!("Unknown activation request");
    }
    let mut focused = false;
    for _ in 0..10 {
        if focus_window().await.is_ok() {
            focused = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let reply = if focused { b"ok\n" } else { b"no\n" };
    stream.write_all(reply).await?;
    Ok(())
}

async fn focus_window() -> anyhow::Result<()> {
    let runtime = PathBuf::from(format!("/run/user/{}", uid()));
    let socket = fs::read_dir(runtime)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                return false;
            };
            let Some(pid) = name
                .strip_prefix("niri.")
                .and_then(|s| s.strip_suffix(".sock"))
                .and_then(|s| s.rsplit('.').next())
                .and_then(|s| s.parse::<u32>().ok())
            else {
                return false;
            };
            fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|s| s.trim() == "niri")
        })
        .context("No running Niri compositor found")?;
    let output = tokio::process::Command::new("niri")
        .env("NIRI_SOCKET", &socket)
        .args(["msg", "--json", "windows"])
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        bail!("Cannot query Niri windows");
    }
    let windows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    let id = windows
        .iter()
        .find(|w| {
            w["pid"].as_u64() == Some(std::process::id() as u64)
                && w["app_id"].as_str() == Some("monarch-lazyvpn")
        })
        .and_then(|w| w["id"].as_u64())
        .context("No window belongs to this LazyVPN instance")?;
    let output = tokio::process::Command::new("niri")
        .env("NIRI_SOCKET", socket)
        .args(["msg", "action", "focus-window", "--id", &id.to_string()])
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        bail!("Cannot focus LazyVPN window");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn missing_session_uses_a_private_per_user_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("run/user/1000");
        let dir = runtime_dir_in(&missing, temp.path()).unwrap();
        assert_eq!(dir, temp.path().join(format!("monarch-lazyvpn-{}", uid())));
        let owner = Instance::acquire(&dir).unwrap().unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert!(Instance::acquire(&dir).unwrap().is_none());
        assert!(!missing.exists());
        drop(owner);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Instance::acquire(&dir).is_err());
    }

    #[test]
    fn simultaneous_launches_have_one_owner() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("runtime");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let instance = Instance::acquire(&dir).unwrap();
                    barrier.wait();
                    instance.is_some()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            1
        );
        assert!(Instance::acquire(&dir).unwrap().is_some());
    }

    #[test]
    fn unsafe_runtime_and_symlink_lock_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("runtime");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Instance::acquire(&dir).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, dir.join("instance.lock")).unwrap();
        assert!(Instance::acquire(&dir).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
    }

    #[test]
    fn unrelated_pid_file_can_be_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let mut instance = Instance::acquire(&temp.path().join("runtime"))
            .unwrap()
            .unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        fs::write(temp.path().join(".pid"), child.id().to_string()).unwrap();
        let result = instance.publish_pid(temp.path());
        child.kill().unwrap();
        child.wait().unwrap();
        result.unwrap();
        assert_eq!(
            fs::read_to_string(temp.path().join(".pid")).unwrap(),
            std::process::id().to_string()
        );
        drop(instance);
        assert!(!temp.path().join(".pid").exists());
    }

    #[test]
    fn lock_child() {
        let Some(dir) = std::env::var_os("LAZYVPN_TEST_LOCK_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let _guard = Instance::acquire(&dir).unwrap().unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(dir.join("activate.sock")).unwrap();
        fs::write(dir.join("ready"), "").unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn killed_owner_releases_lock_and_stale_socket() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("runtime");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "system::instance::tests::lock_child"])
            .env("LAZYVPN_TEST_LOCK_DIR", &dir)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !dir.join("ready").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready = dir.join("ready").exists();
        let busy = ready && Instance::acquire(&dir).unwrap().is_none();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(ready && busy);
        assert!(dir.join("activate.sock").exists());
        let _guard = Instance::acquire(&dir).unwrap().unwrap();
        assert!(!dir.join("activate.sock").exists());
    }
}
