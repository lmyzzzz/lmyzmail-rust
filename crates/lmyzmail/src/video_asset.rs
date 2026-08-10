use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

use sha2::{Digest as _, Sha256};

pub(crate) const VIDEO_ASSET_NAME: &str = "skibidi_toilet_episode_1.mp4";
pub(crate) const VIDEO_ASSET_BYTES: u64 = 15_048_248;
pub(crate) const VIDEO_ASSET_SHA256: &str =
    "0e76229bb77ebcf471aec692fa34709cfbbe3dc192127a852a518e34bdd0ecc7";

pub(crate) fn locate_frozen_video_asset() -> io::Result<PathBuf> {
    let mut candidates = vec![
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join(VIDEO_ASSET_NAME),
        PathBuf::from("/usr/share/lmyzmail/assets").join(VIDEO_ASSET_NAME),
        PathBuf::from("/opt/lmyzmail/assets").join(VIDEO_ASSET_NAME),
    ];
    if let Ok(executable) = std::env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join("assets").join(VIDEO_ASSET_NAME));
    }

    for path in candidates {
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() != VIDEO_ASSET_BYTES {
            continue;
        }
        let mut file = File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let digest = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if digest == VIDEO_ASSET_SHA256 {
            return Ok(path);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("frozen video asset {VIDEO_ASSET_NAME} is unavailable or has the wrong hash"),
    ))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn locates_exact_frozen_asset() {
        let path = locate_frozen_video_asset().expect("frozen video asset must be installed");
        assert_eq!(std::fs::metadata(path).unwrap().len(), VIDEO_ASSET_BYTES);
    }
}
