mod migrate;
mod migrate_store;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use shroudb_sigil_client::SigilClient;

#[derive(Parser)]
#[command(name = "shroudb-sigil-cli", about = "Sigil CLI")]
struct Cli {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:6499", env = "SIGIL_ADDR")]
    addr: String,

    /// Command to execute (e.g., "HEALTH", "SCHEMA REGISTER myapp {...}").
    /// If omitted, starts interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Offline commands that bypass the server (run against the store dir).
    if let Some(subcommand) = offline_subcommand(&cli.command) {
        return run_offline(subcommand).await;
    }

    let mut client = SigilClient::connect(&cli.addr)
        .await
        .with_context(|| format!("failed to connect to {}", cli.addr))?;

    if cli.command.is_empty() {
        // Interactive mode
        interactive(&mut client).await
    } else {
        // Single command mode
        let args: Vec<&str> = cli.command.iter().map(|s| s.as_str()).collect();
        execute(&mut client, &args).await
    }
}

/// An offline command that operates directly on the store, bypassing the
/// Sigil server. Currently: `SCHEMA MIGRATE`.
enum OfflineSubcommand {
    SchemaMigrate { store_dir: PathBuf, dry_run: bool },
}

fn offline_subcommand(command: &[String]) -> Option<OfflineSubcommand> {
    if command.len() < 2 {
        return None;
    }
    if !command[0].eq_ignore_ascii_case("SCHEMA") {
        return None;
    }
    if !command[1].eq_ignore_ascii_case("MIGRATE") {
        return None;
    }

    let mut store_dir: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut iter = command[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--store" => {
                store_dir = iter.next().map(PathBuf::from);
            }
            "--dry-run" => dry_run = true,
            _ => {}
        }
    }

    let store_dir = store_dir?;
    Some(OfflineSubcommand::SchemaMigrate { store_dir, dry_run })
}

async fn run_offline(cmd: OfflineSubcommand) -> anyhow::Result<()> {
    // Initialize logging once here — the offline migrate path wants to
    // surface progress via `tracing::info!`, and the network commands rely
    // on server-side logs.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    match cmd {
        OfflineSubcommand::SchemaMigrate { store_dir, dry_run } => {
            eprintln!(
                "Running SCHEMA MIGRATE against store at {} (dry_run={dry_run})",
                store_dir.display()
            );
            eprintln!("The Sigil server must be stopped for this to be safe.");
            let report = migrate_store::run_migration(&store_dir, dry_run).await?;
            eprintln!();
            eprintln!("Migration report:");
            eprintln!("  migrated:   {}", report.migrated);
            eprintln!("  already v2: {}", report.already_v2);
            eprintln!("  errors:     {}", report.errors.len());
            for err in &report.errors {
                eprintln!("    - {}: {}", err.schema_name, err.message);
            }
            if !report.errors.is_empty() {
                anyhow::bail!(
                    "{} schema(s) failed to migrate — see log above",
                    report.errors.len()
                );
            }
            Ok(())
        }
    }
}

async fn execute(client: &mut SigilClient, args: &[&str]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("empty command");
    }

    match args[0].to_uppercase().as_str() {
        "HEALTH" => {
            client.health().await.context("health check failed")?;
            println!("OK");
        }
        "SCHEMA" if args.len() >= 2 => match args[1].to_uppercase().as_str() {
            "REGISTER" if args.len() >= 4 => {
                let def: serde_json::Value =
                    serde_json::from_str(args[3]).context("invalid JSON")?;
                let version = client
                    .schema_register(args[2], def)
                    .await
                    .context("schema register failed")?;
                println!("registered (version {version})");
            }
            "GET" if args.len() >= 3 => {
                let schema = client
                    .schema_get(args[2])
                    .await
                    .context("schema get failed")?;
                println!("{}", serde_json::to_string_pretty(&schema)?);
            }
            "LIST" => {
                let names = client.schema_list().await.context("schema list failed")?;
                for name in names {
                    println!("{name}");
                }
            }
            _ => anyhow::bail!("usage: SCHEMA REGISTER|GET|LIST ..."),
        },
        "USER" if args.len() >= 3 => match args[1].to_uppercase().as_str() {
            "CREATE" if args.len() >= 5 => {
                let fields: serde_json::Value =
                    serde_json::from_str(args[4]).context("invalid JSON")?;
                let record = client
                    .user_create(args[2], args[3], fields)
                    .await
                    .context("user create failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "entity_id": record.entity_id,
                        "fields": record.fields,
                    }))?
                );
            }
            "IMPORT" if args.len() >= 5 => {
                let fields: serde_json::Value =
                    serde_json::from_str(args[4]).context("invalid JSON")?;
                let record = client
                    .user_import(args[2], args[3], fields)
                    .await
                    .context("user import failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "entity_id": record.entity_id,
                        "fields": record.fields,
                    }))?
                );
            }
            "GET" if args.len() >= 4 => {
                let record = client
                    .user_get(args[2], args[3])
                    .await
                    .context("user get failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "entity_id": record.entity_id,
                        "fields": record.fields,
                    }))?
                );
            }
            "DELETE" if args.len() >= 4 => {
                client
                    .user_delete(args[2], args[3])
                    .await
                    .context("user delete failed")?;
                println!("deleted");
            }
            "VERIFY" if args.len() >= 5 => {
                let valid = client
                    .user_verify(args[2], args[3], args[4])
                    .await
                    .context("verify failed")?;
                println!("{}", if valid { "valid" } else { "invalid" });
            }
            _ => anyhow::bail!("usage: USER CREATE|GET|DELETE|VERIFY ..."),
        },
        "SESSION" if args.len() >= 2 => match args[1].to_uppercase().as_str() {
            "CREATE" if args.len() >= 5 => {
                let tokens = client
                    .session_create(args[2], args[3], args[4], None)
                    .await
                    .context("login failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token,
                        "expires_in": tokens.expires_in,
                    }))?
                );
            }
            "REFRESH" if args.len() >= 4 => {
                let tokens = client
                    .session_refresh(args[2], args[3])
                    .await
                    .context("refresh failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token,
                        "expires_in": tokens.expires_in,
                    }))?
                );
            }
            "REVOKE" if args.len() >= 3 => {
                if args[2].to_uppercase() == "ALL" && args.len() >= 5 {
                    let count = client
                        .session_revoke_all(args[3], args[4])
                        .await
                        .context("revoke all failed")?;
                    println!("revoked {count} sessions");
                } else if args.len() >= 4 {
                    client
                        .session_revoke(args[2], args[3])
                        .await
                        .context("revoke failed")?;
                    println!("revoked");
                } else {
                    anyhow::bail!("usage: SESSION REVOKE <schema> <token> | ALL <schema> <id>");
                }
            }
            _ => anyhow::bail!("usage: SESSION CREATE|REFRESH|REVOKE ..."),
        },
        "PASSWORD" if args.len() >= 2 => match args[1].to_uppercase().as_str() {
            "CHANGE" if args.len() >= 6 => {
                client
                    .password_change(args[2], args[3], args[4], args[5])
                    .await
                    .context("password change failed")?;
                println!("changed");
            }
            "RESET" if args.len() >= 5 => {
                client
                    .password_reset(args[2], args[3], args[4])
                    .await
                    .context("password reset failed")?;
                println!("reset");
            }
            "IMPORT" if args.len() >= 5 => {
                let algo = client
                    .password_import(args[2], args[3], args[4])
                    .await
                    .context("password import failed")?;
                println!("imported (algorithm: {algo})");
            }
            _ => anyhow::bail!("usage: PASSWORD CHANGE|RESET|IMPORT ..."),
        },
        "JWKS" if args.len() >= 2 => {
            let jwks = client.jwks(args[1]).await.context("jwks failed")?;
            println!("{}", serde_json::to_string_pretty(&jwks)?);
        }
        _ => anyhow::bail!("unknown command: {}", args.join(" ")),
    }

    Ok(())
}

async fn interactive(client: &mut SigilClient) -> anyhow::Result<()> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    eprint!("sigil> ");
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            eprint!("sigil> ");
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }

        // Split by whitespace, but preserve JSON in braces
        let args = shell_split(line);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match execute(client, &arg_refs).await {
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
        eprint!("sigil> ");
    }
    Ok(())
}

/// Split a command line by whitespace, preserving JSON objects in braces.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0;

    for ch in input.chars() {
        match ch {
            '{' | '[' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' | ']' => {
                brace_depth -= 1;
                current.push(ch);
            }
            ' ' | '\t' if brace_depth == 0 => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_preserves_json() {
        let args = shell_split(r#"SCHEMA REGISTER myapp {"fields":[{"name":"pw"}]}"#);
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "SCHEMA");
        assert_eq!(args[1], "REGISTER");
        assert_eq!(args[2], "myapp");
        assert!(args[3].starts_with('{'));
    }

    #[test]
    fn shell_split_simple() {
        let args = shell_split("USER GET myapp alice");
        assert_eq!(args, vec!["USER", "GET", "myapp", "alice"]);
    }
}
