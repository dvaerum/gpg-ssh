use std::collections::HashSet;
use std::process::{Command, exit, Stdio};
use log::{error, trace};
use crate::gpg::helper_fn::{cmd_error_handler, get_fingerprint_of_key, get_keygrip, get_name, get_type, is_sub_auth_key};

#[derive(Debug, Clone)]
pub(crate) struct SshKeyInfo {
    pub main_key_id: String,
    pub main_name: String,
    pub auth_fingerprint: String,
    pub auth_keygrip: String,
}

impl SshKeyInfo {
    fn new(
        key_id: &str,
        main_name: &str,
        auth_fingerprint: &str,
        auth_keygrip: &str,
    ) -> Self {
        SshKeyInfo {
            main_key_id: key_id.to_string(),
            main_name: main_name.to_string(),
            auth_fingerprint: auth_fingerprint.to_string(),
            auth_keygrip: auth_keygrip.to_string(),
        }
    }
    
    pub(crate) fn auth_openpgp_hex_string(&self) -> &str {
        &self.auth_fingerprint[(self.auth_fingerprint.len()-8)..]
    }
}


pub(crate) fn gpg_keys(key_ids: Option<Vec<String>>) -> Vec<SshKeyInfo> {
    let mut command = Command::new("gpg");
    command.stdin(Stdio::null())
        .arg("--list-keys")
        .arg("--with-keygrip")
        .arg("--with-colons");

    if let Some(key_ids) = key_ids {
        for key_id in key_ids { command.arg(key_id);}
    }

    let output = command.output()
        .expect("Failed to execute command");

    let mut ssh_keys: Vec<SshKeyInfo> = Vec::new();
    let mut line_count_key: usize = 0;
    let mut line_sub_auth_detected = false;
    
    let mut main_key_id: Option<&str> = None;
    let mut main_uid_name: Option<&str> = None;
    let mut auth_fingerprint: Option<&str> = None;
    let mut auth_keygrip: Option<&str> = None;

    for (row_no, row) in String::from_utf8(output.stdout).expect(
        "Failed at converting GPG (stdout) to String"
    ).trim().split("\n").enumerate() {
        trace!("row_no: {} - row: {}", row_no, row);
        // println!("{:02}: {}", row_no, row);

        if line_count_key >= 1 { line_count_key += 1 }

        if row_no == 0 {
            if get_type(row) == "tru" {
                continue

            } else {
                error!("The 1st line from\
                `gpg --list-keys --with-keygrip --with-colons`\
                 did not start with 'tru'");
                exit(1)
            }
        }

        if get_type(row) == "pub" {
            line_count_key = 1;
            main_key_id = None;
            main_uid_name = None;
            auth_fingerprint = None;
            auth_keygrip = None;
        }

        if line_count_key == 2 {
            if let Some(key_id) = get_fingerprint_of_key(row) { main_key_id = Some(key_id) }
        }

        if let Some(name) = get_name(row) {
            main_uid_name = Some(name);
        }

        if line_sub_auth_detected == false && main_uid_name.is_some() {
            line_sub_auth_detected = is_sub_auth_key(row);
        }

        if line_sub_auth_detected && let Some(fingerprint) = get_fingerprint_of_key(row) {
            auth_fingerprint = Some(fingerprint)
        }

        if line_sub_auth_detected && let Some(fingerprint) = get_keygrip(row) {
            auth_keygrip = Some(fingerprint)
        }

        if let Some(auth_keygrip) = auth_keygrip
            && let Some(auth_fingerprint) = auth_fingerprint
            && let Some(main_key_id) = main_key_id
            && let Some(main_name) = main_uid_name {
            ssh_keys.push(SshKeyInfo::new(main_key_id, main_name, auth_fingerprint, auth_keygrip));
            line_sub_auth_detected = false;
        }
    }

    ssh_keys
}

pub(crate) fn get_enabled_keygrip() -> HashSet<String> {
    let mut command = Command::new("gpg-connect-agent");
    command.stdin(Stdio::null())
        .arg("KEYINFO --list --need-attr=Use-for-ssh");
    let output = command
        .output()
        .expect("Failed to execute command");

    cmd_error_handler(&command, &output);

    let mut keygrip = HashSet::new();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let rows = stdout.trim().lines();
    for row in rows {
        if row == "OK" { break }
        let mut columns = row.split(" ");
        let key = columns.nth(2).unwrap();
        keygrip.insert(key.to_owned());
    }

    keygrip
}
