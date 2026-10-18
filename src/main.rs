use outis_recovery::{parse_pool, recover, AccountKind, Options, Result};
use std::io::{self, IsTerminal, Read, Write};
use zeroize::Zeroizing;

const HELP: &str = "Outis recovery

Usage: outis-recovery [--network SN_MAIN|SN_SEPOLIA] [--index 0]
                      [--kind account|agent] [--pool 0xADDRESS] [--stdin]

The phrase is entered at a hidden prompt. --stdin reads one phrase from standard
input instead. Never place a real phrase in command arguments or shell history.
Output is JSON containing private keys and the derived address. Keep it secret.
Index 0 is the first account; valid indices are 0 through 999.
Any ASCII chain name accepted by Outis is supported. No network calls are made.
This tool does not check deployment, discover balances or broadcast transactions.
";
const ARG_ERROR: &str =
    "Invalid arguments. Run with --help. Enter the phrase only at the prompt or through --stdin";

fn run() -> Result<()> {
    let mut options = Options::default();
    let mut from_stdin = false;
    let mut help = false;
    // Generic errors deliberately never echo arguments: a phrase may have been pasted there.
    let mut args = std::env::args_os().skip(1);
    while let Some(raw) = args.next() {
        let arg = Zeroizing::new(raw.into_string().map_err(|_| ARG_ERROR)?);
        if *arg == "--help" {
            help = true;
            continue;
        }
        if *arg == "--stdin" {
            from_stdin = true;
            continue;
        }
        let (name, inline) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
        if !matches!(name, "--network" | "--index" | "--kind" | "--pool") {
            return Err(ARG_ERROR);
        }
        let value = Zeroizing::new(match inline {
            Some(value) => value.to_owned(),
            None => args
                .next()
                .ok_or(ARG_ERROR)?
                .into_string()
                .map_err(|_| ARG_ERROR)?,
        });
        match name {
            "--network" => options.network = value.to_string(),
            "--index" => {
                if value.is_empty()
                    || value.len() > 3
                    || !value.bytes().all(|b| b.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err("Index must be an integer from 0 through 999");
                }
                options.index = value
                    .parse()
                    .map_err(|_| "Index must be an integer from 0 through 999")?;
            }
            "--kind" => {
                options.kind = match value.as_str() {
                    "account" => AccountKind::Account,
                    "agent" => AccountKind::Agent,
                    _ => return Err("Kind must be account or agent"),
                }
            }
            "--pool" => options.pool = Some(parse_pool(&value)?),
            _ => unreachable!(),
        }
    }
    if help {
        io::stdout()
            .write_all(HELP.as_bytes())
            .map_err(|_| "Could not write help")?;
        return Ok(());
    }
    options.validate()?;
    let phrase = if from_stdin {
        let mut phrase = Zeroizing::new(String::new());
        io::stdin()
            .take(4097)
            .read_to_string(&mut phrase)
            .map_err(|_| "Could not read recovery phrase")?;
        phrase
    } else {
        if !io::stdin().is_terminal() {
            return Err("Use --stdin for piped input, or run in a terminal for the hidden prompt");
        }
        Zeroizing::new(
            rpassword::prompt_password("Recovery phrase (hidden): ")
                .map_err(|_| "Could not read recovery phrase")?,
        )
    };
    if phrase.len() > 4096 {
        return Err("Recovery phrase input is too long");
    }
    let result = recover(&phrase, &options)?;
    drop(phrase);
    eprintln!("Contains private keys. Anyone with this output can control the recovered account.");
    let output = Zeroizing::new(
        serde_json::to_string_pretty(&result).map_err(|_| "Could not encode recovered keys")?,
    );
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| "Could not write recovered keys")
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}
