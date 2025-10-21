use libcrux_ml_kem as mlkem;
use rand::{rngs::OsRng, RngCore};

fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = OsRng;
    let mut seed = [0u8; L];
    rng.fill_bytes(&mut seed);
    seed
}

#[test]
fn mlkem768_roundtrip() {
    let key_seed: [u8; mlkem::KEY_GENERATION_SEED_SIZE] = random_array();
    let key_pair = mlkem::mlkem768::generate_key_pair(key_seed);
    assert!(mlkem::mlkem768::validate_public_key(key_pair.public_key()));
    // Perform encapsulation first so we can validate private key and ciphertext per API

    let enc_seed: [u8; mlkem::ENCAPS_SEED_SIZE] = random_array();
    let (ct, ss1) = mlkem::mlkem768::encapsulate(key_pair.public_key(), enc_seed);
    assert!(mlkem::mlkem768::validate_private_key(key_pair.private_key(), &ct));
    let ss2 = mlkem::mlkem768::decapsulate(key_pair.private_key(), &ct);
    assert_eq!(ss1, ss2);
    assert_eq!(ss1.len(), mlkem::SHARED_SECRET_SIZE);
}
