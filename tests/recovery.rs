use outis_recovery::{decode_phrase, parse_pool, recover, root_from_phrase, AccountKind, Options};
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/recovery-v1-vectors.json")).unwrap()
}

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_outis-recovery"))
        .args(args)
        .current_dir(std::env::temp_dir())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Invalid arguments may close stdin before consuming it.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

#[test]
fn published_vectors() {
    let fixture = vectors();
    let phrase = fixture["phrase"].as_str().unwrap();
    let to_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        to_hex(decode_phrase(phrase).unwrap().as_ref()),
        fixture["entropy"]
    );
    assert_eq!(
        to_hex(root_from_phrase(phrase).unwrap().as_ref()),
        fixture["root"]
    );
    for expected in fixture["accounts"].as_array().unwrap() {
        let options = Options {
            network: expected["network"].as_str().unwrap().into(),
            index: expected["index"].as_u64().unwrap() as u16,
            kind: if expected["kind"] == "agent" {
                AccountKind::Agent
            } else {
                AccountKind::Account
            },
            pool: expected["viewing"]["pool"]
                .as_str()
                .map(|p| parse_pool(p).unwrap()),
        };
        assert_eq!(
            serde_json::to_value(recover(phrase, &options).unwrap()).unwrap(),
            *expected
        );
    }
}

#[test]
fn phrase_normalization_matches_wallet() {
    let fixture = vectors();
    let phrase = fixture["phrase"].as_str().unwrap();
    let expected = decode_phrase(phrase).unwrap();
    let fullwidth = phrase
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                char::from_u32(c as u32 + 0xfee0).unwrap()
            } else {
                c
            }
        })
        .collect::<String>();
    for input in [
        format!(
            " \u{feff}{}\u{feff}",
            phrase.to_uppercase().replace(' ', "\n\t  ")
        ),
        fullwidth,
        phrase.replace(' ', "\u{3000}"),
        phrase.replace(' ', "\u{00a0}"),
    ] {
        assert_eq!(decode_phrase(&input).unwrap(), expected);
    }
    for input in [
        "abandon ".repeat(12),
        phrase.replace("about", "invalidword"),
        format!("{}art", "abandon ".repeat(23)),
        phrase.replace(' ', "\u{0085}"),
        String::new(),
    ] {
        assert!(decode_phrase(&input).is_err());
    }
}

#[test]
fn standalone_binary_matches_vector() {
    let fixture = vectors();
    let result = run(
        &["--stdin", "--network=SN_SEPOLIA", "--pool", "0x5678"],
        fixture["phrase"].as_str().unwrap().as_bytes(),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        fixture["accounts"][1]
    );
    assert!(!String::from_utf8_lossy(&result.stderr).contains(fixture["phrase"].as_str().unwrap()));
}

#[test]
fn rejects_invalid_parameters_without_echoing_secrets_or_keys() {
    let fixture = vectors();
    let phrase = fixture["phrase"].as_str().unwrap();
    let cases = vec![
        vec![phrase],
        vec!["--unknown", phrase],
        vec!["--network", phrase],
        vec!["--kind", phrase],
        vec!["--pool", phrase],
        vec!["--index", phrase],
        vec!["--index", "-1"],
        vec!["--index", "1000"],
        vec!["--index", "01"],
        vec!["--index", "1.5"],
        vec!["--index"],
        vec!["--network", "sn_main"],
        vec!["--network", ""],
        vec!["--network", "SN_MAIN/0"],
        vec!["--network", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        vec!["--pool", "0x0"],
        vec![
            "--pool",
            "0x800000000000000000000000000000000000000000000000000000000000000",
        ],
        vec![
            "--pool",
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ],
    ];
    for args in cases {
        let result = run(&args, phrase.as_bytes());
        assert!(!result.status.success(), "{args:?}");
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(phrase));
    }
    for input in [b"bad phrase".to_vec(), vec![b'a'; 4097], vec![0xff]] {
        let result = run(&["--stdin"], &input);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
    assert!(!run(&[], phrase.as_bytes()).status.success());
    assert!(run(&["--help"], b"").status.success());
}

#[test]
fn validates_library_parameters() {
    for options in [
        Options {
            index: 1000,
            ..Options::default()
        },
        Options {
            network: "sn_main".into(),
            ..Options::default()
        },
        Options {
            pool: Some(crypto_bigint::U256::ZERO),
            ..Options::default()
        },
    ] {
        assert!(options.validate().is_err());
    }
    // Check public shape stays stable even for optional viewing output.
    assert_eq!(
        serde_json::to_value(AccountKind::Account).unwrap(),
        json!("account")
    );
}
