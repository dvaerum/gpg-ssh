extern crate skim;
extern crate core;

mod arguments;
mod gpg;
mod fuzzy;

use arguments::{get_args, SubCommands};
use log::{debug};
use gpg::{create, gpg_keys, ssh_copy_id, unmark_gpg_key_as_ssh_key, get_public_ssh_keys};
use fuzzy::{fzf_set, fzf_copy_id};

fn main() {
    let args = get_args();
    // simple_logger::init_with_level(args.log_level).unwrap();
    env_logger::Builder::default().filter_level(args.log_level)
        .filter_module("tuikit", log::LevelFilter::Info)
        .filter_module("skim", log::LevelFilter::Info)
        .init();
    debug!("{:?}", args);

    match args.sub_commands {
        SubCommands::Create(args) => create(
            args.name,
            args.email,
            None,
            None,
        ),
        SubCommands::List(args) => {
            let ssh_keys = gpg_keys(None);
            for ssh_key in ssh_keys {
                if args.include_key_id {
                    println!("{} {}", ssh_key.main_key_id, ssh_key.main_name)
                } else {
                    println!("{}", ssh_key.main_name)
                }
            }
        },
        SubCommands::Toggle(args) => {
            let ssh_keys = gpg_keys(None);
            if args.disable_all {
                let list_of_keygrip = ssh_keys.iter().map(|info|{
                    info.auth_keygrip.as_str()
                }).collect();
                unmark_gpg_key_as_ssh_key(&list_of_keygrip);
            } else {
                fzf_set(ssh_keys)
            }
        },
        SubCommands::CopyId(args) => {
            let keys = fzf_copy_id();
            if keys.len() >= 1 {
                ssh_copy_id(args.args, keys, args.keep_temp_files).expect("Unknown error")
            }
        },
        SubCommands::PublicKey(args) => {
            if let Some(openpgp_hex_string) = args.lookup_hex {
                let ssh_keys = gpg_keys(None);
                let mut is_match = false;
                for ssh_key_info in ssh_keys {
                    if openpgp_hex_string == ssh_key_info.auth_openpgp_hex_string() {
                        println!(
                            "Key: {}\nName: {}\n\
                            Fingerprint (Auth Subkey): {}\nKeygrip (Auth Subkey): {}",
                            ssh_key_info.main_key_id,
                            ssh_key_info.main_name,
                            ssh_key_info.auth_fingerprint,
                            ssh_key_info.auth_keygrip,
                        );
                        is_match = true;
                        break
                    }
                }
                if ! is_match {
                    println!("Did not find a match for the hex string: 0x{openpgp_hex_string}")
                }
            } else {
                let keys = fzf_copy_id();
                for key in get_public_ssh_keys(keys) {
                    println!("{}", key)
                }
            }
        }
    }
}
