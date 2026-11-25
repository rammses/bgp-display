use super::NativeWireError;
use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// Accept the exact release, optionally followed by one installed-channel label.
pub fn require_target_version(version: &str) -> Result<()> {
    let channel = version
        .strip_prefix("7.24.7 (")
        .and_then(|suffix| suffix.strip_suffix(')'));
    if version == "7.24.7"
        || channel.is_some_and(|label| {
            !label.is_empty() && label.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        })
    {
        Ok(())
    } else {
        bail!("unsupported RouterOS version; requires 7.24.7")
    }
}

/// RouterOS property-value quoting, NOT POSIX or JSON quoting (7.24 Scripting).
/// Other control bytes are preserved here; a checked command constructor must
/// reject unsupported bytes before execution, rather than silently changing data.
pub fn ros_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '$' => escaped.push_str("\\$"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    request: String,
    ok: bool,
    data: Value,
}

pub fn decode_envelope(bytes: &[u8], request: Uuid) -> Result<Value, NativeWireError> {
    let invalid = || NativeWireError {
        code: "invalid-envelope",
    };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    // Derived struct deserialization also accepts positional arrays; require an object.
    if !text
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .starts_with('{')
    {
        return Err(invalid());
    }
    // from_str consumes exactly one JSON value, permitting surrounding JSON
    // whitespace only. Typed fields also reject duplicate envelope keys.
    let envelope: Envelope = serde_json::from_str(text).map_err(|_| invalid())?;
    if envelope.request != request.to_string() {
        return Err(NativeWireError {
            code: "request-mismatch",
        });
    }
    if !envelope.ok {
        return Err(NativeWireError {
            code: "command-rejected",
        });
    }
    Ok(envelope.data)
}

/// Escape controls visibly at the presentation boundary only.
pub fn presentation_text(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() {
            rendered.extend(ch.escape_default());
        } else {
            rendered.push(ch);
        }
    }
    rendered
}

#[cfg(test)]
mod tests {
    use crate::router::mikrotik::{
        decode_envelope, presentation_text, require_target_version, ros_string,
    };
    use serde_json::json;

    // Synthetic envelopes based on the approved protocol, not device captures.
    #[test]
    fn mikrotik_codec_is_exact_and_keeps_native_strings() {
        let id = uuid::Uuid::nil();
        let wire = format!(r#"{{"request":"{id}","ok":true,"data":{{"as":"001234"}}}}"#);
        assert_eq!(
            decode_envelope(wire.as_bytes(), id).unwrap()["as"],
            "001234"
        );
        assert!(decode_envelope(b"failure: command rejected", id).is_err());
        for version in ["7.24.7", "7.24.7 (long-term)"] {
            assert!(require_target_version(version).is_ok());
        }
        for version in ["7.24.70", "7.24.7beta1", "7.24.6", "7.25", ""] {
            assert!(require_target_version(version).is_err());
        }
        assert_eq!(ros_string("a\"\\$\n"), "\"a\\\"\\\\\\$\\n\"");
        assert!(!presentation_text("α\u{1b}[2J\u{7}").contains('\u{1b}'));
    }

    #[test]
    fn mikrotik_codec_rejects_positional_envelope_array() {
        let id = uuid::Uuid::nil();
        let wire = json!([id.to_string(), true, []]).to_string();
        assert!(decode_envelope(wire.as_bytes(), id).is_err());
        let padded = format!(" \r\n{wire}\t ");
        assert!(decode_envelope(padded.as_bytes(), id).is_err());
    }

    #[test]
    fn mikrotik_codec_envelope_requires_one_complete_correlated_object() {
        let id = uuid::Uuid::nil();
        for data in [
            json!([]),
            json!({}),
            json!(null),
            json!("0007"),
            json!(false),
        ] {
            let wire = format!(
                " \r\n{}\t ",
                json!({"request": id, "ok": true, "data": data})
            );
            assert_eq!(decode_envelope(wire.as_bytes(), id).unwrap(), data);
        }
        let valid = json!({"request": id, "ok": true, "data": []}).to_string();
        let invalid = vec![
            "".to_owned(),
            "null".into(),
            "[]".into(),
            "42".into(),
            format!("banner\n{valid}"),
            format!("{valid}\n{valid}"),
            format!("{valid} trailing"),
            valid[..valid.len() - 1].to_owned(),
            json!({"request": uuid::Uuid::from_u128(1), "ok": true, "data": []}).to_string(),
            json!({"request": id, "ok": false, "data": "DEVICE_SECRET"}).to_string(),
            json!({"request": id, "ok": "true", "data": []}).to_string(),
            json!({"request": id, "data": []}).to_string(),
            json!({"ok": true, "data": []}).to_string(),
            json!({"request": id, "ok": true}).to_string(),
            json!({"request": null, "ok": true, "data": []}).to_string(),
            json!({"request": id, "ok": true, "data": [], "extra": "DEVICE_SECRET"}).to_string(),
            format!(r#"{{"request":"{id}","ok":false,"ok":true,"data":[]}}"#),
        ];
        for wire in invalid {
            let error = decode_envelope(wire.as_bytes(), id).unwrap_err();
            assert!(!error.code.contains("DEVICE_SECRET"));
            assert!(!error.to_string().contains("DEVICE_SECRET"));
            assert!(matches!(
                error.code,
                "invalid-envelope" | "request-mismatch" | "command-rejected"
            ));
        }
        let mut invalid_utf8 = valid.into_bytes();
        invalid_utf8.push(0xff);
        assert!(decode_envelope(&invalid_utf8, id).is_err());
    }

    #[test]
    fn mikrotik_codec_version_boundaries_and_safe_errors() {
        for valid in [
            "7.24.7 (stable)",
            "7.24.7 (testing)",
            "7.24.7 (development)",
        ] {
            assert!(require_target_version(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "7.24.7rc1",
            "7.24.7.1",
            "7.24.7 (stable) extra",
            "7.24.7 ()",
            "7.24.7 (stable\n)",
            " 7.24.7",
            "7.24.7 ",
            "7.24.7(stable)",
            "DEVICE_SECRET",
        ] {
            let error = require_target_version(invalid).unwrap_err();
            assert!(!error.to_string().contains("DEVICE_SECRET"));
        }
    }

    #[test]
    fn mikrotik_codec_escaping_and_presentation_never_rewrite_source() {
        let source = "α\"\\$\n\r\t\0\u{7}\u{1b}\u{7f}\u{9b}";
        assert_eq!(
            ros_string(source),
            "\"α\\\"\\\\\\$\\n\\r\\t\0\u{7}\u{1b}\u{7f}\u{9b}\""
        );
        let rendered = presentation_text(source);
        assert!(rendered.starts_with('α'));
        assert!(!rendered.chars().any(char::is_control));
        assert!(rendered.contains("\\n") && rendered.contains("\\u{1b}"));
        assert!(source.contains('\u{1b}') && source.contains('\0'));
        assert_eq!(presentation_text("plain α \"\\$"), "plain α \"\\$");
    }
}
