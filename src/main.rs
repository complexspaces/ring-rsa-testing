// use old_ring_alpha::{rand::SystemRandom, rsa::{RsaKeyPair, RSA_OAEP_2048_8192_SHA256}};
use ring::{rand::SystemRandom, rsa::{RsaKeyPair, RSA_OAEP_2048_8192_SHA256}};

const RSA_PRIVATE_KEY: &[u8] = include_bytes!("../rsa_test_private_key_2048.p8");

const PLAINTEXT: &[u8] = b"secret message";

fn main() {
    println!("Trying crypto cycles...");

    let rng = SystemRandom::new();

    let keypair = RsaKeyPair::from_pkcs8(RSA_PRIVATE_KEY).unwrap();

    let public_key = keypair.public();

    let encrypted = public_key.encrypt_oaep_bytes_less_safe(&RSA_OAEP_2048_8192_SHA256, PLAINTEXT, &rng).expect("able to encrypt with RSA");

    assert_ne!(encrypted.as_ref(), PLAINTEXT);

    let decrypted = keypair.decrypt_oaep_bytes_less_safe(&RSA_OAEP_2048_8192_SHA256, &encrypted).expect("able to decrypt with RSA");

    assert_eq!(decrypted.as_ref(), PLAINTEXT);

    println!("Roundtrip encryption / decrpytion worked!");
}