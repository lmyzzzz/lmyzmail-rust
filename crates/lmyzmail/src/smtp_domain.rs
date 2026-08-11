//! Frozen Java-compatible sender-domain validation for inbound SMTP.

const ACE_PREFIX: &str = "xn--";

const RESERVED_DOMAINS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "localdomain",
    "invalid",
    "test",
    "example",
    "example.com",
    "example.net",
    "example.org",
    "internal",
    "intranet",
    "corp",
    "home",
    "lan",
    "private",
    "mail",
    "email",
    "wpad",
    "autoconfig",
    "autodiscover",
];

const RESERVED_TLDS: &[&str] = &[
    ".localhost",
    ".local",
    ".localdomain",
    ".invalid",
    ".test",
    ".example",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
    ".private",
    ".arpa",
    ".onion",
];

const INVALID_TLDS: &[&str] = &[
    "aa", "zz", "xx", "yy", "tld", "domain", "null", "none", "nil", "temp", "tmp", "fake", "dummy",
    "testing",
];

pub(crate) fn validate_routable_domain(domain: &str) -> Result<(), String> {
    if domain.trim().is_empty() {
        return Err("Domain is empty".to_owned());
    }
    if domain.encode_utf16().count() > 255 {
        return Err("Domain name too long (max 255 characters)".to_owned());
    }
    if is_ip_address(domain) {
        return Err("IP address is not allowed as sender domain".to_owned());
    }
    if domain.starts_with('[') || domain.ends_with(']') {
        return Err("IP address literal is not allowed".to_owned());
    }
    if !domain.contains('.') {
        return Err("Domain must contain at least one dot".to_owned());
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("Domain cannot start or end with a dot".to_owned());
    }
    if domain.contains("..") {
        return Err("Domain cannot contain consecutive dots".to_owned());
    }

    if domain.chars().any(|character| character as u32 > 127) {
        validate_international_domain(domain)
    } else {
        validate_ascii_domain(domain)
    }
}

fn validate_international_domain(domain: &str) -> Result<(), String> {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain must have at least two labels".to_owned());
    }
    for label in &labels {
        if label.is_empty() {
            return Err("Empty label in domain".to_owned());
        }
        if label.encode_utf16().count() > 63 {
            return Err("Label too long (max 63 characters)".to_owned());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Label cannot start or end with hyphen".to_owned());
        }
        for unit in label.encode_utf16() {
            if unit < 0x20 || unit == 0x7f {
                return Err("Label contains ASCII control character".to_owned());
            }
            if unit == b' ' as u16 || unit == b'\t' as u16 {
                return Err("Label contains whitespace".to_owned());
            }
        }
        for character in label.chars() {
            let code = character as u32;
            if code > 0xffff || is_private_use(code) {
                return Err("Label contains invalid Unicode character".to_owned());
            }
            if character == '\u{fffd}' {
                return Err("Label contains invalid byte sequence".to_owned());
            }
        }
    }

    let ascii_domain = idna::domain_to_ascii(domain).ok();
    if ascii_domain
        .as_deref()
        .is_some_and(|value| value.len() > 253)
    {
        return Err("Domain too long after Punycode conversion (max 253 bytes)".to_owned());
    }
    if let Some(ascii_domain) = ascii_domain {
        let ascii_lower = ascii_domain.to_ascii_lowercase();
        if RESERVED_DOMAINS.contains(&ascii_lower.as_str()) {
            return Err("Reserved domain is not allowed".to_owned());
        }
        for reserved_tld in RESERVED_TLDS {
            if ascii_lower.ends_with(reserved_tld)
                || ascii_lower == reserved_tld.trim_start_matches('.')
            {
                return Err(format!("Reserved TLD '{reserved_tld}' is not allowed"));
            }
        }
    }
    Ok(())
}

fn validate_ascii_domain(domain: &str) -> Result<(), String> {
    let domain_lower = domain.to_ascii_lowercase();
    if RESERVED_DOMAINS.contains(&domain_lower.as_str()) {
        return Err(format!("Reserved domain '{domain}' is not allowed"));
    }
    for reserved_tld in RESERVED_TLDS {
        if domain_lower.ends_with(reserved_tld)
            || domain_lower == reserved_tld.trim_start_matches('.')
        {
            return Err(format!("Reserved TLD '{reserved_tld}' is not allowed"));
        }
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain must have at least two labels".to_owned());
    }
    for label in &labels {
        if label.is_empty() {
            return Err("Empty label in domain".to_owned());
        }
        if label.len() > 63 {
            return Err(format!("Label '{label}' exceeds 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("Label '{label}' cannot start or end with hyphen"));
        }
        if label.to_ascii_lowercase().starts_with(ACE_PREFIX) {
            if !is_valid_punycode_label(label) {
                return Err(format!("Invalid Punycode label: {label}"));
            }
        } else if label.len() == 1 {
            if !label.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return Err(format!("Invalid character in label '{label}'"));
            }
        } else if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("Invalid characters in label '{label}'"));
        }
    }

    let tld = labels[labels.len() - 1].to_ascii_lowercase();
    if tld.len() < 2 {
        return Err("TLD must be at least 2 characters".to_owned());
    }
    if tld.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("TLD cannot be all numeric".to_owned());
    }
    if INVALID_TLDS.contains(&tld.as_str()) {
        return Err(format!("Invalid or non-existent TLD '{tld}'"));
    }
    Ok(())
}

fn is_valid_punycode_label(label: &str) -> bool {
    if label.len() < ACE_PREFIX.len() + 1 {
        return false;
    }
    let lower = label.to_ascii_lowercase();
    lower.strip_prefix(ACE_PREFIX).is_some_and(|suffix| {
        suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn is_private_use(code: u32) -> bool {
    (0xe000..=0xf8ff).contains(&code)
        || (0xf0000..=0xffffd).contains(&code)
        || (0x100000..=0x10fffd).contains(&code)
}

fn is_ip_address(value: &str) -> bool {
    is_ipv4(value)
        || value.chars().filter(|&character| character == ':').count() > 1
        || (value.starts_with('[') && value.ends_with(']'))
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u16>().is_ok_and(|number| number <= 255)
        })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn frozen_ascii_reasons_are_exact() {
        assert_eq!(
            validate_routable_domain("example.com"),
            Err("Reserved domain 'example.com' is not allowed".to_owned())
        );
        assert_eq!(
            validate_routable_domain("mx.test"),
            Err("Reserved TLD '.test' is not allowed".to_owned())
        );
        assert_eq!(
            validate_routable_domain("bad_name.com"),
            Err("Invalid characters in label 'bad_name'".to_owned())
        );
        assert_eq!(
            validate_routable_domain("_.com"),
            Err("Invalid character in label '_'".to_owned())
        );
    }

    #[test]
    fn frozen_idn_boundaries_match_java_shape() {
        assert!(validate_routable_domain("bücher.de").is_ok());
        assert!(validate_routable_domain("xn--bcher-kva.de").is_ok());
        assert_eq!(
            validate_routable_domain("\u{e000}.de"),
            Err("Label contains invalid Unicode character".to_owned())
        );
        assert_eq!(
            validate_routable_domain("😀.de"),
            Err("Label contains invalid Unicode character".to_owned())
        );
    }

    proptest! {
        #[test]
        fn ascii_labels_with_safe_shape_are_never_rejected_for_character_syntax(
            label in "[a-z0-9][a-z0-9-]{0,20}[a-z0-9]",
        ) {
            let domain = format!("{label}.de");
            prop_assert!(validate_routable_domain(&domain).is_ok());
        }
    }
}
