[TOC]

# gpg-ssh

This is a small program I wrote to generate GnuPG/OpenPGP keys,
using `ed25519` (Elliptic Curve) algorithm,
to be used with the SSH client.

```bash
gpg-ssh --help
# A CLI to help managing SSH keys using GnuPG keystore
# 
# Usage: gpg-ssh [OPTIONS] --ssh-auth-sock <SSH_AUTH_SOCK> <COMMAND>
# 
# Commands:
#   create      Generate SSH key (ed25519)
#   list        List all the SSH Keys in GnuPG
#   toggle      Toggle which GPG are enabled ot be used by the SSH agent
#   copy-id     Parse public key to `ssh-copy-id` and have it upload to the server
#   public-key  Prints the Public SSH Key for the selected GPG key
#   help        Print this message or the help of the given subcommand(s)
# 
# Options:
#       --log-level <LOG_LEVEL>          Set the log level. The options are error, warn, info, debug, trace [env: LOG_LEVEL=] [default: INFO]
#       --ssh-auth-sock <SSH_AUTH_SOCK>  Path to the GPG Agent socket for SSH [env: SSH_AUTH_SOCK=/run/user/1000/gnupg/S.gpg-agent.ssh]
#   -h, --help                           Print help
#   -V, --version                        Print version
```


# My notes about how to generate the GPG keys by hand

Create the main certificate/key. You can set the `EXPIRATION_DATE` to `never` or
select how many days `<n>`, weeks `<n>w`, months `<n>m` or years `<n>y` until the should expire.

**Note:** If this key only will be used to `ssh` into server you can go ahead and
set the `EXPIRATION_DATE` to never because it is never check by the SSH Server.
You can manually add an experation date to the `~/.ssh/authorized_keys` by
manually adding the option `expiry-time="YYYYMMDD"`.
[Read more](https://man.archlinux.org/man/sshd.8#expiry-time=_timespec_)

```bash
# Optional commnet
gpg --quick-generate-key 'USER_NAME (OPTIONAL_COMMENT) <YOUR.EMAIL@EXAMPLE.COM>' ed25519 cert EXPIRATION_DATE

# Without optional comment
gpg --quick-generate-key 'USER_NAME <YOUR.EMAIL@EXAMPLE.COM>' ed25519 cert EXPIRATION_DATE
```

When you have created the main certificate/key, you will get a message looking like this.

```
gpg: revocation certificate stored as '/home/dennis/.gnupg/openpgp-revocs.d/D604F89376D476B6E10E314B06748D23AAB1D083.rev'
public and secret key created and signed.

pub   ed25519 2024-09-21 [C]
      D604F89376D476B6E10E314B06748D23AAB1D083
uid                      USER_NAME (OPTIONAL_COMMENT) <YOUR.EMAIL@EXAMPLE.COM>
```

Copy the ID of the key and use it to create following 3 subkeys.

**Note:** Again from what understand,
if the keys are only used for SSH when one can just set the `EXPIRATION_DATE` to `never`,
because as meantion earlier and earlier note, the SSH Server does not check for the `EXPIRATION_DATE`.
I however will set the EXPIRATION_DATE to `1y` to get a reminder about rotating my GPG/SSH keys.

```bash
KEYFP=D604F89376D476B6E10E314B06748D23AAB1D083

gpg --quick-add-key $KEYFP ed25519 sign EXPIRATION_DATE
gpg --quick-add-key $KEYFP cv25519 encr EXPIRATION_DATE
gpg --quick-add-key $KEYFP ed25519 auth EXPIRATION_DATE
```

Now that all the keys are create,
the `gpg-agent` needs to be told which keys can be exposed to the SSH Client
(By default non are exposed).
To expose a key, you need the `Keygrip` which you get by run the following command

```bash
gpg --with-keygrip --list-keys $KEYFP
# pub   ed25519 2024-09-21 [C]
#       D604F89376D476B6E10E314B06748D23AAB1D083
#       Keygrip = 75EA32640943A4BD6DF8D823AE2380B154B09EC7
# uid           [ultimate] USER_NAME (OPTIONAL_COMMENT) <YOUR.EMAIL@EXAMPLE.COM>
# sub   ed25519 2024-09-21 [S]
#       Keygrip = 5CD6E490FE2DA282B12A3DE25809F331C2F236B5
# sub   cv25519 2024-09-21 [E]
#       Keygrip = 775DC6269563262460C4069B3020D3B1F97019F9
# sub   ed25519 2024-09-21 [A]
#       Keygrip = 32E0FB1B126484A4FEF42E5AEFA69ED699BFF89B
```

Now run the command `gpg-connect-agent "KEYATTR <Keygrip> Use-for-ssh: true" /bye`
with the `Keygrid` from the the certification (`[A]`)

```bash
gpg-connect-agent "KEYATTR 32E0FB1B126484A4FEF42E5AEFA69ED699BFF89B Use-for-ssh: true" /bye
```

**Deprecated**

> write the `Keygrid` from the the certification (`[A]`) to the `~/.gnupg/sshcontrol` file
> (one `Keygrid` per line).
>
> ```bash
> echo "32E0FB1B126484A4FEF42E5AEFA69ED699BFF89B" | tee -a $HOME/.gnupg/sshcontrol
> ```


Now use `ssh-add` to list the key.

**WARNING:** If this does not work, something is wrong and
the `ssh` command is also not gonna work.

```bash
ssh-add -L
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlb2hUJyf+AJcGD7PqVcl2oGUmk+XCTeY95pbulTMlX (none)
```

The last think, export the public ssh key.

```bash
# gpg --export-ssh-key D604F89376D476B6E10E314B06748D23AAB1D083

gpg --export-ssh-key $KEYFP
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlb2hUJyf+AJcGD7PqVcl2oGUmk+XCTeY95pbulTMlX openpgp:0xAAB1D083

# Note: "0xAAB1D083" is the last 8 hex ditis of the fingerprint for the Auth "[A]" key
```

To list all the `Keygrid` enabled to be used by `ssh` run the following command.

```bash
gpg-connect-agent 'KEYINFO --list --need-attr=Use-for-ssh' /bye
# S KEYINFO 32E0FB1B126484A4FEF42E5AEFA69ED699BFF89B D - - - P - - -
# OK
```
