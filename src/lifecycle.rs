use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, plugins};

pub fn install(systemd: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    run(Command::new("cargo")
        .arg("install")
        .arg("--path")
        .arg(&repo_root))?;
    ensure_config_dir()?;
    plugins::install_bundled_plugins(&config_dir().join("plugins"))?;
    if systemd {
        install_systemd(&repo_root)?;
    }
    println!("clawhip install complete");
    Ok(())
}

pub fn update(restart: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    run(Command::new("git")
        .arg("-C")
        .arg(&repo_root)
        .arg("pull")
        .arg("--ff-only"))?;
    run(Command::new("cargo")
        .arg("install")
        .arg("--path")
        .arg(&repo_root)
        .arg("--force"))?;
    ensure_config_dir()?;
    plugins::install_bundled_plugins(&config_dir().join("plugins"))?;
    if restart {
        restart_systemd_if_present()?;
    }
    println!("clawhip update complete");
    Ok(())
}

pub fn uninstall(remove_systemd: bool, remove_config: bool) -> Result<()> {
    stop_systemd_if_present()?;
    let binary_path = cargo_bin_dir().join("clawhip");
    if binary_path.exists() {
        fs::remove_file(&binary_path)?;
        println!("Removed {}", binary_path.display());
    }
    if remove_systemd {
        uninstall_systemd_if_present()?;
    }
    if remove_config {
        let config_dir = config_dir();
        if config_dir.exists() {
            fs::remove_dir_all(&config_dir)?;
            println!("Removed {}", config_dir.display());
        }
    }
    println!("clawhip uninstall complete");
    Ok(())
}

fn current_repo_root() -> Result<PathBuf> {
    let dir = env::current_dir()?;
    if dir.join("Cargo.toml").exists() && dir.join("src").exists() {
        Ok(dir)
    } else {
        Err("run this command from the clawhip git clone root".into())
    }
}

fn ensure_config_dir() -> Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir)?;
    println!("Ensured config dir {}", dir.display());
    Ok(())
}

fn config_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".clawhip")
}

fn cargo_bin_dir() -> PathBuf {
    env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into())).join(".cargo")
        })
        .join("bin")
}

fn install_systemd(repo_root: &Path) -> Result<()> {
    let unit_src = repo_root.join("deploy").join("clawhip.service");
    let unit_dest = PathBuf::from("/etc/systemd/system/clawhip.service");
    run(Command::new("sudo")
        .arg("cp")
        .arg(&unit_src)
        .arg(&unit_dest))?;
    run(Command::new("sudo").arg("systemctl").arg("daemon-reload"))?;
    run(Command::new("sudo")
        .arg("systemctl")
        .arg("enable")
        .arg("--now")
        .arg("clawhip"))?;
    Ok(())
}

fn uninstall_systemd_if_present() -> Result<()> {
    let unit_dest = PathBuf::from("/etc/systemd/system/clawhip.service");
    if unit_dest.exists() {
        let _ = run(Command::new("sudo")
            .arg("systemctl")
            .arg("disable")
            .arg("--now")
            .arg("clawhip"));
        let _ = run(Command::new("sudo").arg("rm").arg("-f").arg(&unit_dest));
        let _ = run(Command::new("sudo").arg("systemctl").arg("daemon-reload"));
    }
    Ok(())
}

fn restart_systemd_if_present() -> Result<()> {
    let unit_dest = PathBuf::from("/etc/systemd/system/clawhip.service");
    if unit_dest.exists() {
        let _ = run(Command::new("sudo")
            .arg("systemctl")
            .arg("restart")
            .arg("clawhip"));
    }
    Ok(())
}

fn stop_systemd_if_present() -> Result<()> {
    let unit_dest = PathBuf::from("/etc/systemd/system/clawhip.service");
    if unit_dest.exists() {
        let _ = run(Command::new("sudo")
            .arg("systemctl")
            .arg("stop")
            .arg("clawhip"));
    }
    Ok(())
}

fn run(command: &mut Command) -> Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}").into())
    }
}
