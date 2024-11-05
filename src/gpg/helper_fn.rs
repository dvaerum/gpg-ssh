use std::process::{Command, exit, Output};
use std::str::from_utf8;
use log::error;

pub(crate) fn get_column(line: &str, column: usize) -> &str {
    let mut columns = line.split(":");
    let result = columns.nth(column);
    result.unwrap()
}

pub(super) fn get_type(line: &str) -> &str {
    get_column(line, 0)
}


pub(super) fn get_fingerprint_of_key(line: &str) -> Option<&str> {
    if get_type(line) == "fpr" {
        Some(get_column(line, 9))
    } else {
        None
    }
}

pub(super) fn get_name(line: &str) -> Option<&str> {
    if get_type(line) == "uid" {
        Some(get_column(line, 9))
    } else {
        None
    }
}

pub(super) fn get_keygrip(line: &str) -> Option<&str> {
    if get_type(line) == "grp" {
        Some(get_column(line, 9))
    } else {
        None
    }
}

pub(super) fn is_sub_auth_key(line: &str) -> bool {
    get_column(line, 0) == "sub" &&
    get_column(line, 11) == "a"
}

pub(super) fn cmd_error_handler(command: &Command, output: &Output) {
    if output.status.success() { return; }

    let mut stdout;
    let mut stderr;

    if output.stdout.len() > 0 {
        stdout = String::from("Stdout: ");
        stdout.push_str(from_utf8(&output.stdout).unwrap());
    } else {
        stdout = String::from("Stdout: ");
    }

    if output.stderr.len() > 0 {
        stderr = String::from("Stderr: ");
        stderr.push_str(from_utf8(&output.stderr).unwrap());
    } else {
        stderr = String::from("No Stderr")
    }

    error!(
        "Failed CMD: {:?} - Args: {:?} - {:?} - {:?} - Exit code: {}",
        command.get_program(),
        command.get_args(),
        stdout, stderr,
        output.status.code().unwrap(),
    );

    exit(1);
}
