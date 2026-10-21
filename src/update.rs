//! Release discovery and verified downloads, independent of the desktop UI.

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::Duration;

pub mod inplace;
#[cfg(windows)]
pub mod windows;

/// Page offered to the user when they want to fetch a newer build by hand.
pub const RELEASE_PAGE: &str = "https://cnb.cool/SecLab/FengheShell";

/// FengheShell has no public release feed yet, so the automatic check is
/// switched off. Point this at a releases API endpoint once one exists and
/// `check()` starts working again with no other change.
const RELEASE_API: Option<&str> = None;

/// Only release assets served from this path are accepted (see `Release::asset`).
/// TODO(FengheShell): set both this and `RELEASE_API` when the project has its
/// own release feed.
const RELEASE_DOWNLOAD_PATH: &str = "/fengheshell/fengheshell/releases/download";

#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

fn version(tag: &str) -> Option<(u32, u32, u32)> {
    let mut parts = tag.strip_prefix('v').unwrap_or(tag).split('.');
    let value = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(value)
}

pub fn newer_release(body: &str, current: &str) -> Result<Option<Release>> {
    let release: Release = serde_json::from_str(body).context("Invalid release response")?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let latest = version(&release.tag_name).context("Invalid stable release version")?;
    let current = version(current.split('-').next().unwrap_or(current))
        .context("Invalid installed version")?;
    Ok((latest > current).then_some(release))
}

pub fn check() -> Result<Option<Release>> {
    let Some(api) = RELEASE_API else {
        // No release feed configured yet — report "nothing newer" instead of
        // querying someone else's releases.
        return Ok(None);
    };
    let body = ureq::get(api)
        .set("User-Agent", "fengheshell-update-check")
        .timeout(Duration::from_secs(15))
        .call()
        .context("Could not check GitHub releases")?
        .into_string()?;
    newer_release(&body, env!("CARGO_PKG_VERSION"))
}

impl Release {
    pub fn windows_installer(&self) -> Result<&Asset> {
        self.asset(&format!("fengheshell-{}-windows-x86_64.msi", self.tag_name))
    }

    /// The release file named `name`, accepted only from this repository's
    /// release download path for this tag and only with a SHA-256 digest.
    pub fn asset(&self, name: &str) -> Result<&Asset> {
        ensure!(version(&self.tag_name).is_some(), "Invalid release version");
        let asset = self
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .with_context(|| format!("This release has no {name} yet. Try again later."))?;
        let url = url::Url::parse(&asset.browser_download_url)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("github.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == format!("{RELEASE_DOWNLOAD_PATH}/{}/{name}", self.tag_name),
            "Unexpected installer download URL"
        );
        ensure!(asset.size > 0, "The installer is empty");
        asset.sha256()?;
        Ok(asset)
    }
}

impl Asset {
    pub fn sha256(&self) -> Result<&str> {
        let digest = self
            .digest
            .as_deref()
            .and_then(|s| s.strip_prefix("sha256:"))
            .context(
                "This release has no SHA-256 checksum. Use the release page to install manually.",
            )?;
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid installer checksum"
        );
        Ok(digest)
    }

    pub fn download(&self, output: impl Write, progress: impl FnMut(u64, u64)) -> Result<()> {
        let response = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(60))
            .build()
            .get(&self.browser_download_url)
            .set("User-Agent", "fengheshell-updater")
            .call()
            .context("Could not download the installer")?;
        copy_verified(
            response.into_reader(),
            output,
            self.size,
            self.sha256()?,
            progress,
        )
    }
}

fn copy_verified(
    mut input: impl Read,
    mut output: impl Write,
    size: u64,
    digest: &str,
    mut progress: impl FnMut(u64, u64),
) -> Result<()> {
    let mut hash = Sha256::new();
    let mut received = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .context("Installer download interrupted")?;
        if count == 0 {
            break;
        }
        received += count as u64;
        ensure!(
            received <= size,
            "Installer is larger than the release metadata"
        );
        output
            .write_all(&buffer[..count])
            .context("Could not save the installer")?;
        hash.update(&buffer[..count]);
        progress(received, size);
    }
    ensure!(received == size, "Installer download is incomplete");
    let actual = format!("{:x}", hash.finalize());
    if !actual.eq_ignore_ascii_case(digest) {
        bail!("Installer checksum does not match the release");
    }
    output.flush()?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/update/download.rs"]
mod tests;
