use std::process::{Command, Stdio};
use log::debug;
use crate::gpg::helper_fn::cmd_error_handler;

pub(crate) fn mark_gpg_key_as_ssh_key<S: AsRef<str> + std::fmt::Debug>(
    list_of_keygrip: &Vec<S>,
) {
    if list_of_keygrip.len() == 0 { return; }

    let mut command = Command::new("gpg-connect-agent");
    command.stdin(Stdio::null());

    for keygrip in list_of_keygrip {
        command.arg(format!("KEYATTR {} Use-for-ssh: true", keygrip.as_ref()));
    }

    let output = command
        .output()
        .expect("Failed to execute command");

    cmd_error_handler(&command, &output);
    debug!("Added the keygrip: {:?}", list_of_keygrip);
}

pub(crate) fn unmark_gpg_key_as_ssh_key<S: AsRef<str> + std::fmt::Debug>(
    list_of_keygrip: &Vec<S>,
) {
    if list_of_keygrip.len() == 0 { return; }
    
    let mut command = Command::new("gpg-connect-agent");
    command.stdin(Stdio::null());

    for keygrip in list_of_keygrip {
        command.arg(format!("KEYATTR {} Use-for-ssh: false", keygrip.as_ref()));
    }

    let output = command
        .output()
        .expect("Failed to execute command");

    cmd_error_handler(&command, &output);
    debug!("Remove the keygrip: {:?}", list_of_keygrip);
}
