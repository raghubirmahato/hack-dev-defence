//! `hdd-proxy` binary: load the strict YAML configuration, resolve the R-03 secrets from the environment, start the two
//! listeners and wait for Ctrl+C. `--version` and `--help` are side-effect free; `admin reset-password <username>` is the
//! documented offline reset (Addendum 2 item 7) that prints a one-time password to the terminal.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

/// The command line of the binary.
enum Command {
    /// Run the proxy.
    Run {
        /// The YAML configuration file.
        config_path: String,
    },
    /// Print a one-time password for a user (offline, operator only).
    ResetPassword {
        /// The YAML configuration file (for its `data_dir`).
        config_path: String,
        /// The login name to reset.
        username: String,
    },
    /// Print the version.
    Version,
    /// Print the usage.
    Help,
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&arguments) {
        Ok(command) => command,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "hdd-proxy: {message}");
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Version => {
            let _ = writeln!(
                std::io::stdout(),
                "{} {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        Command::Help => {
            let _ = write_help(std::io::stdout());
            ExitCode::SUCCESS
        }
        Command::ResetPassword {
            config_path,
            username,
        } => run_async(async move { reset_password(&config_path, &username) }),
        Command::Run { config_path } => run_async(async move { run_server(&config_path).await }),
    }
}

/// Build a single-threaded-safe runtime and map the result to an exit code.
fn run_async<F>(future: F) -> ExitCode
where
    F: std::future::Future<Output = Result<(), String>>,
{
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "hdd-proxy: cannot start the async runtime: {error}"
            );
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(future) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "hdd-proxy: {message}");
            ExitCode::from(1)
        }
    }
}

/// Parse the command line strictly (no positional surprises; `--config` is required for every command that reads it).
fn parse_args(arguments: &[String]) -> Result<Command, String> {
    let mut config_path: Option<String> = None;
    let mut admin_reset: Option<String> = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "--config" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "`--config` needs a file path".to_owned())?;
                config_path = Some(value.clone());
                index += 2;
            }
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            "admin" => {
                let subcommand = arguments.get(index + 1).ok_or_else(|| {
                    "`admin` needs a subcommand; available: reset-password <username>".to_owned()
                })?;
                if subcommand != "reset-password" {
                    return Err(format!(
                        "unknown admin subcommand `{subcommand}`; available: reset-password"
                    ));
                }
                let username = arguments
                    .get(index + 2)
                    .ok_or_else(|| "`reset-password` needs a username".to_owned())?;
                admin_reset = Some(username.clone());
                index += 3;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`; run with --help"));
            }
            other => {
                return Err(format!("unexpected argument `{other}`; run with --help"));
            }
        }
    }
    let config_path = config_path.ok_or_else(|| {
        "the `--config <path>` option is required (for example demo/hdd-dev.yaml)".to_owned()
    })?;
    match admin_reset {
        Some(username) => Ok(Command::ResetPassword {
            config_path,
            username,
        }),
        None => Ok(Command::Run { config_path }),
    }
}

/// Print the usage to `out`.
fn write_help(mut out: impl std::io::Write) -> std::io::Result<()> {
    writeln!(
        out,
        "hdd-proxy {}: the Hack Dev Defence SQL-injection reverse proxy (HK1 demo track)\n\
         \n\
         USAGE:\n\
         \x20 hdd-proxy --config <path> [--version] [--help]\n\
         \x20 hdd-proxy --config <path> admin reset-password <username>\n\
         \n\
         The admin bootstrap token is read from the environment variable named by `admin_token_env` in the\n\
         configuration file. There is no default token: the admin listener refuses to start when the variable is\n\
         missing (R-03). The proxy listener itself does not accept admin commands.\n\
         \n\
         The dashboard is served on `admin_listen` (loopback by default). TLS termination is out of scope for HK1:\n\
         run the proxy behind Caddy or Cloudflare.",
        env!("CARGO_PKG_VERSION")
    )
}

/// Run the proxy: configuration, secrets, account store, listeners, Ctrl+C.
async fn run_server(config_path: &str) -> Result<(), String> {
    let config = hdd_proxy::Config::load(Path::new(config_path)).map_err(|error| error.message)?;
    let validated = config.validate().map_err(|error| error.message)?;
    // R-03: the admin bootstrap token is a required environment value; no default exists.
    let secrets = validated
        .resolve_secrets(|name| std::env::var(name).ok())
        .map_err(|error| error.message)?;
    let auth = hdd_proxy::auth::AccountAuth::load(&validated, &secrets.admin_token)
        .map_err(|error| error.message)?;
    let state = hdd_proxy::state::AppState::new(&validated, &secrets, Arc::new(auth))
        .map_err(|error| error.message)?;
    let running =
        hdd_proxy::server::start(Arc::clone(&state), validated.listen, validated.admin_listen)
            .await?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(
        out,
        "hdd-proxy {}: HK1 demo track (TLS termination is out of scope; run behind Caddy/Cloudflare)",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out, "  proxy listener: http://{}", running.proxy_addr);
    let _ = writeln!(
        out,
        "  admin dashboard: http://{} (loopback token/account login)",
        running.admin_addr
    );
    // R1-9: a non-loopback admin listener is refused by validation unless the operator set the explicit ack.
    if !validated.admin_listen.ip().is_loopback() {
        let _ = writeln!(
            out,
            "  WARNING: admin_listen {} is NOT loopback and admin_non_loopback_ack: true is set; the admin surface \
             and its login are exposed to the network",
            running.admin_addr
        );
    }
    for site in state.sites() {
        let _ = writeln!(
            out,
            "  site {} -> {} mode {} strictness {:?}",
            site.host(),
            site.origin_display(),
            site.mode().as_str(),
            site.strictness()
        );
    }
    match state.ai.model() {
        Some(model) => {
            let _ = writeln!(
                out,
                "  AI explanations: enabled ({model}); the API key is read from the configured environment \
                 variable at call time and never printed"
            );
        }
        None => {
            let _ = writeln!(
                out,
                "  AI explanations: off (no `ai:` block, or its API key environment variable is not set)"
            );
        }
    }
    let _ = writeln!(
        out,
        "  the admin bootstrap token comes from the environment variable named in `admin_token_env` and is never printed"
    );
    let _ = writeln!(out, "press Ctrl+C to stop");
    let _ = out.flush();
    drop(out);

    let _ = tokio::signal::ctrl_c().await;
    running.shutdown().await;
    Ok(())
}

/// The documented offline password reset (Addendum 2 item 7): prints a one-time password to the terminal.
fn reset_password(config_path: &str, username: &str) -> Result<(), String> {
    let config = hdd_proxy::Config::load(Path::new(config_path)).map_err(|error| error.message)?;
    let validated = config.validate().map_err(|error| error.message)?;
    let password = hdd_proxy::accounts::reset_password(&validated.data_dir, username)
        .map_err(|error| error.to_string())?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "one-time password for `{username}`: {password}");
    let _ = writeln!(
        out,
        "sign in with it, then change it from the account page; it is shown only now"
    );
    let _ = out.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn config_is_required_for_run() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["--config"])).is_err());
    }

    #[test]
    fn version_and_help_need_no_config() {
        assert!(matches!(
            parse_args(&args(&["--version"])),
            Ok(Command::Version)
        ));
        assert!(matches!(parse_args(&args(&["--help"])), Ok(Command::Help)));
    }

    #[test]
    fn reset_password_parses_with_config() {
        let parsed = parse_args(&args(&[
            "--config",
            "demo/hdd-dev.yaml",
            "admin",
            "reset-password",
            "owner",
        ]));
        assert!(matches!(
            parsed,
            Ok(Command::ResetPassword {
                config_path,
                username
            }) if config_path == "demo/hdd-dev.yaml" && username == "owner"
        ));
    }

    #[test]
    fn unknown_arguments_are_rejected() {
        assert!(parse_args(&args(&["--config", "x", "--nope"])).is_err());
        assert!(parse_args(&args(&["--config", "x", "positional"])).is_err());
        assert!(parse_args(&args(&["--config", "x", "admin", "bogus"])).is_err());
    }
}
