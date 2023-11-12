use std::fmt::Display;

use log;
use security_framework::{
    base::Error,
    passwords::{delete_generic_password, get_generic_password, set_generic_password},
};

const SERVICE_NAME: &str = "my_rio_service";
const ACCOUNT_NAME: &str = "sgrigorev";

#[derive(Debug)]
pub enum PasswordError {
    KeyChainError(Error),
    IOError(),
}

impl Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::KeyChainError(e) => write!(f, "Problem with the KeyChain: {}", e),
            PasswordError::IOError() => write!(f, "Terminal IO error"),
        }
    }
}

impl std::error::Error for PasswordError {}

impl Into<PasswordError> for Error {
    fn into(self) -> PasswordError {
        PasswordError::KeyChainError(self)
    }
}

pub type ErrorOr<A> = Result<A, PasswordError>;

/// Return the password.
/// In asks for a new password if that was not stored in the system.
pub fn generate_password() -> ErrorOr<String> {
    match get_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
        Ok(pass) => Ok(String::from_utf8(pass).expect("Password has incorrect UTF-8 symbols")),
        Err(e) => {
            log::warn!(
                "Password was not found or request was reject: {}",
                e.message().unwrap_or_default()
            );

            // create a new password
            if let Err(e) = delete_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
                log::warn!(
                    "Old password was not deleted (if that exists): {}",
                    e.message().unwrap_or_default()
                );
            }

            let mut buffer = String::new();
            println!("Enter a password: ");
            std::io::stdin()
                .read_line(&mut buffer)
                .map_err(|_| PasswordError::IOError())?;

            let new_password = buffer.trim_end();

            set_generic_password(SERVICE_NAME, ACCOUNT_NAME, new_password.as_bytes())
                .map_err(|e| e.into())?;
            log::info!(
                "New password was stored in KeyChain: [{}] / [{}]",
                SERVICE_NAME,
                ACCOUNT_NAME
            );

            // return the password to be used later
            Ok(new_password.to_owned())
        }
    }
}
