use clap::{Parser, ValueEnum};
use hex::ToHex;
use libcrux_ml_kem as mlkem;
use rand::{rngs::OsRng, RngCore};

/// Generate cryptographically secure random bytes.
fn random_array<const L: usize>() -> [u8; L] {
    // Note: For production systems consider using a DRBG per NIST SP 800-90A.
    let mut rng = OsRng;
    let mut seed = [0u8; L];
    rng.fill_bytes(&mut seed);
    seed
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Param {
    #[value(alias = "512")]
    P512,
    #[value(alias = "768")]
    P768,
    #[value(alias = "1024")]
    P1024,
}

#[derive(Parser, Debug)]
#[command(name = "mlkem-cli", about = "Demo of libcrux-ml-kem (ML-KEM) usage")] 
struct Args {
    /// Parameter set to use (512, 768, or 1024)
    #[arg(short, long, value_enum, default_value_t = Param::P768)]
    param: Param,

    /// Print raw materials (keys, ciphertext, shared secret) in hex
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    match args.param {
        Param::P512 => run_demo_512(args.verbose),
        Param::P768 => run_demo_768(args.verbose),
        Param::P1024 => run_demo_1024(args.verbose),
    }
}

fn run_demo_512(verbose: bool) {
    // Key generation requires KEY_GENERATION_SEED_SIZE bytes of randomness.
    let key_seed: [u8; mlkem::KEY_GENERATION_SEED_SIZE] = random_array();
    let key_pair = mlkem::mlkem512::generate_key_pair(key_seed);

    let enc_seed: [u8; mlkem::ENCAPS_SEED_SIZE] = random_array();
    let (ciphertext, shared_secret_enc) = mlkem::mlkem512::encapsulate(key_pair.public_key(), enc_seed);
    // Validate per FIPS prior to decapsulation
    assert!(mlkem::mlkem512::validate_public_key(key_pair.public_key()));
    assert!(mlkem::mlkem512::validate_private_key(key_pair.private_key(), &ciphertext));
    let shared_secret_dec = mlkem::mlkem512::decapsulate(key_pair.private_key(), &ciphertext);

    println!("ML-KEM-512 round-trip successful: {} bytes shared secret", mlkem::SHARED_SECRET_SIZE);
    assert_eq!(shared_secret_enc, shared_secret_dec, "shared secrets mismatch");

    if verbose {
        print_materials("ML-KEM-512", key_pair.public_key().as_ref(), key_pair.private_key().as_ref(), ciphertext.as_ref(), &shared_secret_enc);
    }
}

fn run_demo_768(verbose: bool) {
    let key_seed: [u8; mlkem::KEY_GENERATION_SEED_SIZE] = random_array();
    let key_pair = mlkem::mlkem768::generate_key_pair(key_seed);

    let enc_seed: [u8; mlkem::ENCAPS_SEED_SIZE] = random_array();
    let (ciphertext, shared_secret_enc) = mlkem::mlkem768::encapsulate(key_pair.public_key(), enc_seed);
    assert!(mlkem::mlkem768::validate_public_key(key_pair.public_key()));
    assert!(mlkem::mlkem768::validate_private_key(key_pair.private_key(), &ciphertext));
    let shared_secret_dec = mlkem::mlkem768::decapsulate(key_pair.private_key(), &ciphertext);

    println!("ML-KEM-768 round-trip successful: {} bytes shared secret", mlkem::SHARED_SECRET_SIZE);
    assert_eq!(shared_secret_enc, shared_secret_dec, "shared secrets mismatch");

    if verbose {
        print_materials("ML-KEM-768", key_pair.public_key().as_ref(), key_pair.private_key().as_ref(), ciphertext.as_ref(), &shared_secret_enc);
    }
}

fn run_demo_1024(verbose: bool) {
    let key_seed: [u8; mlkem::KEY_GENERATION_SEED_SIZE] = random_array();
    let key_pair = mlkem::mlkem1024::generate_key_pair(key_seed);

    let enc_seed: [u8; mlkem::ENCAPS_SEED_SIZE] = random_array();
    let (ciphertext, shared_secret_enc) = mlkem::mlkem1024::encapsulate(key_pair.public_key(), enc_seed);
    assert!(mlkem::mlkem1024::validate_public_key(key_pair.public_key()));
    assert!(mlkem::mlkem1024::validate_private_key(key_pair.private_key(), &ciphertext));
    let shared_secret_dec = mlkem::mlkem1024::decapsulate(key_pair.private_key(), &ciphertext);

    println!("ML-KEM-1024 round-trip successful: {} bytes shared secret", mlkem::SHARED_SECRET_SIZE);
    assert_eq!(shared_secret_enc, shared_secret_dec, "shared secrets mismatch");

    if verbose {
        print_materials("ML-KEM-1024", key_pair.public_key().as_ref(), key_pair.private_key().as_ref(), ciphertext.as_ref(), &shared_secret_enc);
    }
}

fn print_materials(name: &str, pk: &[u8], sk: &[u8], ct: &[u8], ss: &[u8]) {
    println!("=== {} materials (hex) ===", name);
    println!("public_key   ({} B): {}", pk.len(), pk.encode_hex::<String>());
    println!("private_key  ({} B): {}", sk.len(), sk.encode_hex::<String>());
    println!("ciphertext   ({} B): {}", ct.len(), ct.encode_hex::<String>());
    println!("sharedsecret ({} B): {}", ss.len(), ss.encode_hex::<String>());
}
