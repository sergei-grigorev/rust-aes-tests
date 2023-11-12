use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use argon2::Argon2;
use rand_core::{OsRng, RngCore};
use std::fmt::Display;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct PasswordError(aes_gcm::Error);

impl Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Problem with the AES: {}", self.0.to_string())
    }
}

impl std::error::Error for PasswordError {}

impl Into<PasswordError> for aes_gcm::Error {
    fn into(self) -> PasswordError {
        PasswordError(self)
    }
}

pub type Result<A> = core::result::Result<A, PasswordError>;

/// Create AES key and encrypt the phrase.
pub fn create_cert(master_password: &mut String) -> Result<()> {
    let mut key_derivation_salt = [0u8; 16];
    OsRng.fill_bytes(&mut key_derivation_salt);

    let mut output_key_material = [0u8; 32];
    let alg = Argon2::default();

    // generate new AES key
    alg.hash_password_into(
        master_password.as_bytes(),
        &key_derivation_salt,
        &mut output_key_material,
    )
    .expect("AES Key generation failed");

    let key: &Key<Aes256Gcm> = &output_key_material.into();

    // clear password
    master_password.zeroize();

    let my_secure_text = "Hello world";
    println!("Run Encryption, text: {}", my_secure_text);
    println!("Raw buffer: {:?}", my_secure_text.as_bytes());

    // generate cipher and encryp the message
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, my_secure_text.as_ref())
        .map_err(|e| e.into())?;

    println!("Encrypted");
    println!("Raw buffer: {:?}", ciphertext);
		println!("Salt: {:?}", nonce);

    // decrypt the message
    let decrypted = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| e.into())?;

    println!("Decrypted text: {:?}", String::from_utf8(decrypted));

    Ok(())
}
