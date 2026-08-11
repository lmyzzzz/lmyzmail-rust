#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct StaticAsset {
    pub(crate) body: &'static [u8],
    pub(crate) content_type: &'static str,
}

const INDEX: &[u8] = include_bytes!("../assets/web-static/BOOT-INF/classes/static/index.html");
const CRINGE: &[u8] = include_bytes!("../assets/web-static/BOOT-INF/classes/static/cringe.html");
const FAVICON: &[u8] = include_bytes!("../assets/web-static/BOOT-INF/classes/static/favicon.ico");
const INTERNET_NL_BADGE: &[u8] = include_bytes!(
    "../assets/web-static/BOOT-INF/classes/static/images/embed-badge-emailtest-internet.nl.svg"
);

pub(crate) fn resolve(path: &str) -> Option<StaticAsset> {
    let (body, content_type): (&'static [u8], &'static str) = match path {
        "/" | "/index.html" => (INDEX, "text/html; charset=UTF-8"),
        "/cringe.html" => (CRINGE, "text/html; charset=UTF-8"),
        "/favicon.ico" => (FAVICON, "image/x-icon"),
        "/images/embed-badge-emailtest-internet.nl.svg" => (INTERNET_NL_BADGE, "image/svg+xml"),
        _ => return None,
    };
    Some(StaticAsset { body, content_type })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    use super::{CRINGE, FAVICON, INDEX, INTERNET_NL_BADGE, resolve};

    fn sha256(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    #[test]
    fn embedded_assets_match_the_frozen_oracle_jar_members() {
        assert_eq!(INDEX.len(), 143_603);
        assert_eq!(
            sha256(INDEX),
            "2de2ead2a3e3166e2868e808a33cf6b7d737057226608634932f6e35e4a9cc59"
        );
        assert_eq!(CRINGE.len(), 49_259);
        assert_eq!(
            sha256(CRINGE),
            "07af2d09deb255d1c3087b63800813f91291a917216ddcf4543ba46ae39411c7"
        );
        assert_eq!(FAVICON.len(), 11_085);
        assert_eq!(
            sha256(FAVICON),
            "0fd834a5512a8768180da63c804fd0f6fbbeec75ad7c08944e6e32c258fd93a5"
        );
        assert_eq!(INTERNET_NL_BADGE.len(), 18_418);
        assert_eq!(
            sha256(INTERNET_NL_BADGE),
            "b27d228d5d3b108824517783ab12fb31c98121539dec866d8b647aa8314dead2"
        );
    }

    #[test]
    fn resolver_exposes_only_the_frozen_public_paths() {
        assert_eq!(resolve("/").unwrap().body, INDEX);
        assert_eq!(resolve("/index.html").unwrap().body, INDEX);
        assert_eq!(resolve("/cringe.html").unwrap().body, CRINGE);
        assert_eq!(resolve("/favicon.ico").unwrap().body, FAVICON);
        assert_eq!(
            resolve("/images/embed-badge-emailtest-internet.nl.svg")
                .unwrap()
                .body,
            INTERNET_NL_BADGE
        );

        for path in [
            "/images/missing.svg",
            "/%2e%2e/application.properties",
            "/../application.properties",
            "/assets/../application.properties",
            "index.html",
        ] {
            assert_eq!(resolve(path), None, "unexpected static path: {path}");
        }
    }
}
