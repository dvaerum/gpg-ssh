use std::fmt::{Display};
use std::process::{Command, Stdio};
use log::trace;
use super::gpg_keys;
use super::helper_fn::{cmd_error_handler, get_fingerprint_of_key};
use super::set::mark_gpg_key_as_ssh_key;

#[derive(Debug)]
pub(crate) enum KeyAlgo {
    ED25519,
}

impl Display for KeyAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            KeyAlgo::ED25519 => "ed25519",
        }.to_string())
    }
}


fn add_sub_key(key_id: &str, key_algo: &str, key_type: &str) {
    let mut command = Command::new("gpg");
    command.stdin(Stdio::null())
        .arg("--quick-add-key")
        .arg(key_id)
        .arg(key_algo)
        .arg(key_type)
        .arg("never");
    let output = command
        .output()
        .expect("Failed to execute command");

    cmd_error_handler(&command, &output);
}

fn add_sub_key_sign(key_id: &str, key_algo: &KeyAlgo) {
    add_sub_key(key_id, key_algo.to_string().as_str(), "sign")
}

fn add_sub_key_encr(key_id: &str, key_algo: &KeyAlgo) {
    add_sub_key(
        key_id,
        match key_algo {
            KeyAlgo::ED25519 => "cv25519",
        },
        "encr"
    )
}

fn add_sub_key_auth(key_id: &str, key_algo: &KeyAlgo) {
    add_sub_key(key_id, key_algo.to_string().as_str(), "auth")
}


pub(crate) fn create(
    name: String,
    email: String,
    comment: Option<String>,
    key_algo: Option<KeyAlgo>,
) {
    let key_algo = key_algo.unwrap_or(KeyAlgo::ED25519);

    let mut command = Command::new("gpg");
    command.stdin(Stdio::null()).stderr(Stdio::piped()).stdout(Stdio::piped())
        .arg("--with-colons")
        .arg("--quick-generate-key")
        .arg(format!("{name} ({comment}) <{email}>",
             comment=comment.unwrap_or("SSH Key".to_string())))
        .arg(key_algo.to_string())
        .arg("cert")
        .arg("never");
    let output = command
        .output()
        .expect("Failed to execute command");

    cmd_error_handler(&command, &output);


    let stdout = String::from_utf8(output.stdout).unwrap();
    let stdout_as_lines = stdout.trim().lines().rev();

    let mut fpr_key_id = None;
    // let mut grp_keygrip = None;
    // let mut uid_name = None;
    for row in stdout_as_lines {
        trace!("line: {row}");
        if row.len() == 0 { break }

        if let Some(id) = get_fingerprint_of_key(row) { fpr_key_id = Some(id) }
        // if let Some(keygrip) = get_keygrip(row) { grp_keygrip = Some(keygrip) }
        // if let Some(name) = get_name(row) { uid_name = Some(name) }
    }

    if let Some(key_id) = fpr_key_id {
        add_sub_key_sign(key_id, &key_algo);
        add_sub_key_encr(key_id, &key_algo);
        add_sub_key_auth(key_id, &key_algo);

        let key_ids = vec![key_id.to_string()];
        let key_ssh_info= gpg_keys(Some(key_ids));

        for key_ssh in key_ssh_info {
            mark_gpg_key_as_ssh_key(&vec![key_ssh.auth_keygrip])
        }
    }
}
