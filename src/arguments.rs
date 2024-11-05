use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use clap::{Args, command, Parser, Subcommand, value_parser};
use regex::Regex;

/// Generate SSH key (ed25519)
#[derive(Args, Debug, PartialEq)]
pub struct CreateArgs {
    #[arg(
        long,
        env = "CERT_NAME",
        help = "Set the name of the certificate",
    )]
    pub name: String,

    #[arg(
        long,
        env = "CERT_EMAIL",
        help = "Set the email of the certificate",
    )]
    pub email: String,
}

/// List all the SSH Keys in GnuPG
#[derive(Args, Debug, PartialEq)]
pub struct ListArgs {
    #[arg(
        long,
        default_value_t = false,
        help = "Include the key id",
    )]
    pub include_key_id: bool,
}

/// Toggle which GPG are enabled ot be used by the SSH agent
#[derive(Args, Debug, PartialEq)]
pub struct ToggleArgs {
    #[arg(
        long,
        default_value_t = false,
        help = "disable all GPG key marked for SSH usage",
    )]
    pub disable_all: bool,
}

/// Parse public key to `ssh-copy-id` and have it upload to the server
#[derive(Args, Debug, PartialEq)]
pub struct CopyIdArgs {
    #[arg(
        value_delimiter = ' ',
        num_args = 1..,
        required = true,
        help = "Arguments passed to `ssh-copy-id`",
    )]
    pub args: Vec<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Keep the temporary files create (used for debugging)",
    )]
    pub keep_temp_files: bool,
}

fn verify_lookup_hex(hex_string: &str) -> Result<String, Error> {
    let hex_string= hex_string.to_uppercase();
    let re = Regex::new(r"(0x)?(?<hex_string>[0-9A-F]{8})$").unwrap();
    if let Some(captures) = re.captures(&hex_string) {
        Ok(captures["hex_string"].to_string())
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "The value was not a 8 chars hex string"))
    }
}

/// Prints the Public SSH Key for the selected GPG key
#[derive(Args, Debug, PartialEq)]
pub struct PublicKeyArgs {
    #[arg(
        long,
        value_parser = verify_lookup_hex,
        help = "Lookup and return GPG Key used to create the SSH",
    )]
    pub lookup_hex: Option<String>,
}

#[derive(Args, Debug, PartialEq)]
pub struct CompletionArgs {
}

#[derive(Subcommand, Debug, PartialEq)]
pub(crate) enum SubCommands {
    Create(CreateArgs),
    List(ListArgs),
    Toggle(ToggleArgs),
    CopyId(CopyIdArgs),
    PublicKey(PublicKeyArgs),
}

/// A CLI to help managing SSH keys using GnuPG keystore
#[derive(Parser, Debug, PartialEq)]
#[command(author, version, about, long_about = None)]
pub struct MainArgs {
    #[arg(
        long,
        default_value_t = log::LevelFilter::Info,
        env = "LOG_LEVEL",
        help = format!("Set the log level. The options are {}",
        log::Level::iter().map(|err| err.to_string().to_lowercase())
        .collect::<std::vec::Vec<String>>()
        .join(", "))
    )]
    pub log_level: log::LevelFilter,

    #[arg(
        long,
        env = "SSH_AUTH_SOCK",
        value_parser = value_parser!(PathBuf),
        help = "Path to the GPG Agent socket for SSH",
    )]
    pub ssh_auth_sock: PathBuf,

    #[command(subcommand)]
    pub sub_commands: SubCommands,
}


//noinspection RsUnresolvedPath
pub fn get_args() -> MainArgs {
    MainArgs::parse()
}
