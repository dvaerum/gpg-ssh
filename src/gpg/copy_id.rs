use std::process::{Command, Stdio};
use log::{debug, warn};
use tempfile::NamedTempFile;
use std::io::Write;
use super::helper_fn::cmd_error_handler;


pub(crate) fn get_public_ssh_keys(
    public_key_ids: Vec<String>,
) -> Vec<String> {
    let ssh_public_key: Vec<String> = public_key_ids.iter().map(|public_key| {
        let mut gpg_command = Command::new("gpg");
        gpg_command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .arg("--export-ssh-key")
            .arg(public_key);
        let gpg_output = gpg_command
            .output()
            .expect("Failed to execute command");

        cmd_error_handler(&gpg_command, &gpg_output);

        debug!("SSH Public Key: {}", String::from_utf8_lossy(gpg_output.stdout.as_slice()));
        String::from_utf8(gpg_output.stdout).unwrap().trim().to_string()
    }).collect();

    ssh_public_key
}


pub(crate) fn ssh_copy_id(
    args: Vec<String>,
    public_key_ids: Vec<String>,
    keep_temp_files: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ssh_public_key = get_public_ssh_keys(public_key_ids);

    let mut file = NamedTempFile::with_suffix(".pub")?;
    write!(file, "{}\n", ssh_public_key.as_slice().join("\n"))?;
    file.flush()?;

    let mut command = Command::new("ssh-copy-id");
    command.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    command.arg("-f");
    command.arg("-i");
    command.arg(file.path());

    let mut detect_argument_i = Vec::new();
    for arg in args {
        if arg.as_str() == "-i" || detect_argument_i.len() == 1 {
            detect_argument_i.push(arg);
        } else { 
            command.arg(arg);
        }
    }

    if detect_argument_i.len() > 0 {
        warn!("SSH Public key is already provided, so the following arguments are skipped: {:?}", detect_argument_i)
    }
    
    let output = command
        .output()
        .expect("Failed to execute command");

    if ! keep_temp_files {
        file.close()?;
    }

    cmd_error_handler(&command, &output);

    Ok(())
}