{ naersk-lib
, gnupg
, ssh-copy-id
}:
naersk-lib.buildPackage {
  buildInputs = [ gnupg ssh-copy-id ];
  src = ./.;
}
