// passhash is the repo-native helper used by appmesh-auth to
// seed the authentication service's initial administrator password hash. It reads the password from stdin
// (never from argv or the environment) and writes only the bcrypt hash.
use std::io::Read;
use std::process::exit;

use zeroize::Zeroizing;

const MAX_PASSWORD_LEN: usize = 4096;

fn main() {
    let mut password = Zeroizing::new(Vec::new());
    if std::io::stdin()
        .take(MAX_PASSWORD_LEN as u64 + 1)
        .read_to_end(&mut password)
        .is_err()
    {
        eprintln!("password input is unreadable");
        exit(1);
    }
    if password.last() == Some(&b'\n') {
        password.pop();
    }
    if password.last() == Some(&b'\r') {
        password.pop();
    }
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        eprintln!("password input is empty or too long");
        exit(1);
    }
    if password.len() > 72 {
        eprintln!("failed to hash password");
        exit(1);
    }
    match bcrypt::hash(password.as_slice(), 10) {
        Ok(hash) => println!("{hash}"),
        Err(_) => {
            eprintln!("failed to hash password");
            exit(1);
        }
    }
}
