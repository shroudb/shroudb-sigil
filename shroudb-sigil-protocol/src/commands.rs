use std::collections::HashMap;

use shroudb_acl::{AclRequirement, Scope};
use shroudb_sigil_core::schema::Schema;

/// Parsed Sigil wire protocol command.
#[derive(Debug)]
pub enum SigilCommand {
    /// Authenticate this connection with a token.
    Auth {
        token: String,
    },

    // Schema
    SchemaRegister {
        schema: Schema,
    },
    SchemaGet {
        name: String,
    },
    SchemaList,

    // User
    UserCreate {
        schema: String,
        user_id: String,
        fields: HashMap<String, serde_json::Value>,
    },
    UserGet {
        schema: String,
        user_id: String,
    },
    UserDelete {
        schema: String,
        user_id: String,
    },
    UserImport {
        schema: String,
        user_id: String,
        fields: HashMap<String, serde_json::Value>,
    },
    UserUpdate {
        schema: String,
        user_id: String,
        fields: HashMap<String, serde_json::Value>,
    },
    UserVerify {
        schema: String,
        user_id: String,
        password: String,
    },
    UserLookup {
        schema: String,
        field_name: String,
        field_value: String,
    },

    // Session
    SessionCreate {
        schema: String,
        user_id: String,
        password: String,
        metadata: Option<serde_json::Value>,
    },
    SessionCreateByField {
        schema: String,
        field_name: String,
        field_value: String,
        password: String,
        metadata: Option<serde_json::Value>,
    },
    SessionRefresh {
        schema: String,
        token: String,
    },
    SessionRevoke {
        schema: String,
        token: String,
    },
    SessionRevokeAll {
        schema: String,
        user_id: String,
    },
    SessionList {
        schema: String,
        user_id: String,
    },

    // Password
    PasswordChange {
        schema: String,
        user_id: String,
        old_password: String,
        new_password: String,
    },
    PasswordReset {
        schema: String,
        user_id: String,
        new_password: String,
    },
    PasswordImport {
        schema: String,
        user_id: String,
        hash: String,
        metadata: Option<serde_json::Value>,
    },

    // JWT
    Jwks {
        schema: String,
    },

    // Operational
    Health,
}

impl SigilCommand {
    /// The ACL requirement for this command.
    /// Checked against the connection's `AuthContext` before dispatch.
    pub fn acl_requirement(&self) -> AclRequirement {
        match self {
            // Pre-auth / public
            SigilCommand::Auth { .. } | SigilCommand::Health => AclRequirement::None,

            // Public: JWKS is for external token verification
            SigilCommand::Jwks { .. } => AclRequirement::None,

            // Schema introspection (shape is not sensitive)
            SigilCommand::SchemaGet { .. } | SigilCommand::SchemaList => AclRequirement::None,

            // Schema mutation is a structural change → admin
            SigilCommand::SchemaRegister { .. } => AclRequirement::Admin,

            // Read operations on user data
            SigilCommand::UserGet { schema, .. }
            | SigilCommand::UserLookup { schema, .. }
            | SigilCommand::SessionList { schema, .. } => AclRequirement::Namespace {
                ns: format!("sigil.{schema}.*"),
                scope: Scope::Read,
                tenant_override: None,
            },

            // Write operations on user data
            SigilCommand::UserCreate { schema, .. }
            | SigilCommand::UserImport { schema, .. }
            | SigilCommand::UserUpdate { schema, .. }
            | SigilCommand::UserDelete { schema, .. }
            | SigilCommand::UserVerify { schema, .. }
            | SigilCommand::SessionCreate { schema, .. }
            | SigilCommand::SessionCreateByField { schema, .. }
            | SigilCommand::SessionRefresh { schema, .. }
            | SigilCommand::SessionRevoke { schema, .. }
            | SigilCommand::SessionRevokeAll { schema, .. }
            | SigilCommand::PasswordChange { schema, .. }
            | SigilCommand::PasswordReset { schema, .. }
            | SigilCommand::PasswordImport { schema, .. } => AclRequirement::Namespace {
                ns: format!("sigil.{schema}.*"),
                scope: Scope::Write,
                tenant_override: None,
            },
        }
    }
}

/// Parse raw RESP3 command arguments into a SigilCommand.
///
/// Arguments come as string slices: `["SCHEMA", "REGISTER", "myapp", "{...}"]`.
pub fn parse_command(args: &[&str]) -> Result<SigilCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "AUTH" => {
            if args.len() < 2 {
                return Err("AUTH <token>".into());
            }
            Ok(SigilCommand::Auth {
                token: args[1].to_string(),
            })
        }
        "SCHEMA" => parse_schema(args),
        "USER" => parse_user(args),
        "SESSION" => parse_session(args),
        "PASSWORD" => parse_password(args),
        "JWKS" => parse_jwks(args),
        "HEALTH" => Ok(SigilCommand::Health),
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn parse_schema(args: &[&str]) -> Result<SigilCommand, String> {
    if args.len() < 2 {
        return Err("SCHEMA requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "REGISTER" => {
            if args.len() < 4 {
                return Err("SCHEMA REGISTER <name> <json>".into());
            }
            let name = args[2].to_string();
            let mut schema: Schema =
                serde_json::from_str(args[3]).map_err(|e| format!("invalid schema JSON: {e}"))?;
            schema.name = name;
            Ok(SigilCommand::SchemaRegister { schema })
        }
        "GET" => {
            if args.len() < 3 {
                return Err("SCHEMA GET <name>".into());
            }
            Ok(SigilCommand::SchemaGet {
                name: args[2].to_string(),
            })
        }
        "LIST" => Ok(SigilCommand::SchemaList),
        sub => Err(format!("unknown SCHEMA subcommand: {sub}")),
    }
}

fn parse_user(args: &[&str]) -> Result<SigilCommand, String> {
    if args.len() < 2 {
        return Err("USER requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "CREATE" => {
            if args.len() < 5 {
                return Err("USER CREATE <schema> <id> <json>".into());
            }
            let fields: HashMap<String, serde_json::Value> =
                serde_json::from_str(args[4]).map_err(|e| format!("invalid fields JSON: {e}"))?;
            Ok(SigilCommand::UserCreate {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                fields,
            })
        }
        "GET" => {
            if args.len() < 4 {
                return Err("USER GET <schema> <id>".into());
            }
            Ok(SigilCommand::UserGet {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
            })
        }
        "LOOKUP" => {
            if args.len() < 5 {
                return Err("USER LOOKUP <schema> <field> <value>".into());
            }
            Ok(SigilCommand::UserLookup {
                schema: args[2].to_string(),
                field_name: args[3].to_string(),
                field_value: args[4].to_string(),
            })
        }
        "IMPORT" => {
            if args.len() < 5 {
                return Err("USER IMPORT <schema> <id> <json>".into());
            }
            let fields: HashMap<String, serde_json::Value> =
                serde_json::from_str(args[4]).map_err(|e| format!("invalid fields JSON: {e}"))?;
            Ok(SigilCommand::UserImport {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                fields,
            })
        }
        "UPDATE" => {
            if args.len() < 5 {
                return Err("USER UPDATE <schema> <id> <json>".into());
            }
            let fields: HashMap<String, serde_json::Value> =
                serde_json::from_str(args[4]).map_err(|e| format!("invalid fields JSON: {e}"))?;
            Ok(SigilCommand::UserUpdate {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                fields,
            })
        }
        "DELETE" => {
            if args.len() < 4 {
                return Err("USER DELETE <schema> <id>".into());
            }
            Ok(SigilCommand::UserDelete {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
            })
        }
        "VERIFY" => {
            if args.len() < 5 {
                return Err("USER VERIFY <schema> <id> <password>".into());
            }
            Ok(SigilCommand::UserVerify {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                password: args[4].to_string(),
            })
        }
        sub => Err(format!("unknown USER subcommand: {sub}")),
    }
}

fn parse_session(args: &[&str]) -> Result<SigilCommand, String> {
    if args.len() < 2 {
        return Err("SESSION requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "CREATE" => {
            if args.len() < 5 {
                return Err("SESSION CREATE <schema> <id> <password> [META <json>]".into());
            }
            let metadata = find_option(args, "META")
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| format!("invalid META JSON: {e}"))?;
            Ok(SigilCommand::SessionCreate {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                password: args[4].to_string(),
                metadata,
            })
        }
        "LOGIN" => {
            // SESSION LOGIN <schema> <field> <value> <password> [META <json>]
            if args.len() < 6 {
                return Err(
                    "SESSION LOGIN <schema> <field> <value> <password> [META <json>]".into(),
                );
            }
            let metadata = find_option(args, "META")
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| format!("invalid META JSON: {e}"))?;
            Ok(SigilCommand::SessionCreateByField {
                schema: args[2].to_string(),
                field_name: args[3].to_string(),
                field_value: args[4].to_string(),
                password: args[5].to_string(),
                metadata,
            })
        }
        "REFRESH" => {
            if args.len() < 4 {
                return Err("SESSION REFRESH <schema> <token>".into());
            }
            Ok(SigilCommand::SessionRefresh {
                schema: args[2].to_string(),
                token: args[3].to_string(),
            })
        }
        "REVOKE" => {
            if args.len() < 3 {
                return Err("SESSION REVOKE <schema> <token> | ALL <schema> <id>".into());
            }
            if args[2].to_uppercase() == "ALL" {
                if args.len() < 5 {
                    return Err("SESSION REVOKE ALL <schema> <id>".into());
                }
                Ok(SigilCommand::SessionRevokeAll {
                    schema: args[3].to_string(),
                    user_id: args[4].to_string(),
                })
            } else {
                if args.len() < 4 {
                    return Err("SESSION REVOKE <schema> <token>".into());
                }
                Ok(SigilCommand::SessionRevoke {
                    schema: args[2].to_string(),
                    token: args[3].to_string(),
                })
            }
        }
        "LIST" => {
            if args.len() < 4 {
                return Err("SESSION LIST <schema> <id>".into());
            }
            Ok(SigilCommand::SessionList {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
            })
        }
        sub => Err(format!("unknown SESSION subcommand: {sub}")),
    }
}

fn parse_password(args: &[&str]) -> Result<SigilCommand, String> {
    if args.len() < 2 {
        return Err("PASSWORD requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "CHANGE" => {
            if args.len() < 6 {
                return Err("PASSWORD CHANGE <schema> <id> <old> <new>".into());
            }
            Ok(SigilCommand::PasswordChange {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                old_password: args[4].to_string(),
                new_password: args[5].to_string(),
            })
        }
        "RESET" => {
            if args.len() < 5 {
                return Err("PASSWORD RESET <schema> <id> <new>".into());
            }
            Ok(SigilCommand::PasswordReset {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                new_password: args[4].to_string(),
            })
        }
        "IMPORT" => {
            if args.len() < 5 {
                return Err("PASSWORD IMPORT <schema> <id> <hash> [META <json>]".into());
            }
            let metadata = find_option(args, "META")
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| format!("invalid META JSON: {e}"))?;
            Ok(SigilCommand::PasswordImport {
                schema: args[2].to_string(),
                user_id: args[3].to_string(),
                hash: args[4].to_string(),
                metadata,
            })
        }
        sub => Err(format!("unknown PASSWORD subcommand: {sub}")),
    }
}

fn parse_jwks(args: &[&str]) -> Result<SigilCommand, String> {
    if args.len() < 2 {
        return Err("JWKS <schema>".into());
    }
    Ok(SigilCommand::Jwks {
        schema: args[1].to_string(),
    })
}

/// Find an optional keyword argument: `KEY value` in the args list.
fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_schema_register() {
        let args = vec![
            "SCHEMA",
            "REGISTER",
            "myapp",
            r#"{"fields":[{"name":"pw","field_type":"string","annotations":{"credential":true}}]}"#,
        ];
        let cmd = parse_command(&args).unwrap();
        assert!(matches!(cmd, SigilCommand::SchemaRegister { schema } if schema.name == "myapp"));
    }

    #[test]
    fn parse_user_create() {
        let args = vec![
            "USER",
            "CREATE",
            "myapp",
            "user1",
            r#"{"password":"secret","org":"acme"}"#,
        ];
        let cmd = parse_command(&args).unwrap();
        assert!(
            matches!(cmd, SigilCommand::UserCreate { schema, user_id, .. } if schema == "myapp" && user_id == "user1")
        );
    }

    #[test]
    fn parse_session_create_with_meta() {
        let args = vec![
            "SESSION",
            "CREATE",
            "myapp",
            "user1",
            "password",
            "META",
            r#"{"role":"admin"}"#,
        ];
        let cmd = parse_command(&args).unwrap();
        assert!(matches!(
            cmd,
            SigilCommand::SessionCreate {
                metadata: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn parse_session_revoke_all() {
        let args = vec!["SESSION", "REVOKE", "ALL", "myapp", "user1"];
        let cmd = parse_command(&args).unwrap();
        assert!(
            matches!(cmd, SigilCommand::SessionRevokeAll { schema, user_id } if schema == "myapp" && user_id == "user1")
        );
    }

    #[test]
    fn parse_password_import() {
        let args = vec![
            "PASSWORD",
            "IMPORT",
            "myapp",
            "user1",
            "$argon2id$v=19$hash",
        ];
        let cmd = parse_command(&args).unwrap();
        assert!(
            matches!(cmd, SigilCommand::PasswordImport { hash, .. } if hash == "$argon2id$v=19$hash")
        );
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(&["HEALTH"]).unwrap();
        assert!(matches!(cmd, SigilCommand::Health));
    }

    #[test]
    fn unknown_command_errors() {
        assert!(parse_command(&["NOPE"]).is_err());
    }

    #[test]
    fn empty_command_errors() {
        assert!(parse_command(&[]).is_err());
    }
}
