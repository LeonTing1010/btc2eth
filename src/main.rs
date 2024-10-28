// This Rust program takes a hexadecimal private key as input and generates corresponding Bitcoin and Ethereum addresses.
// It uses the `k256` crate for ECDSA key handling, the `bitcoin` crate for Bitcoin address generation,
// and the `ethers` crate for Ethereum address handling. The public key is derived from the private key,
// and Keccak-256 hashing is applied to generate the Ethereum address.
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::key::PublicKey;
use ethers::types::Address as EthAddress;
use hex;
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256}; // Import Keccak256 for hashing

fn private_key_to_addresses(private_key_hex: &str) -> Result<(String, EthAddress), String> {
    // Decode the private key from hex
    let private_key_bytes = hex::decode(private_key_hex).map_err(|e| e.to_string())?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes).map_err(|e| e.to_string())?;

    // Generate the public key
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Create Bitcoin address (P2PKH)
    let btc_public_key =
        PublicKey::from_slice(verifying_key.to_bytes().as_slice()).map_err(|e| e.to_string())?;
    let btc_address = Address::p2pkh(&btc_public_key, Network::Bitcoin).to_string();

    // Create Ethereum address
    let public_key_bytes = verifying_key.to_bytes();

    // Hash the public key using Keccak-256
    let mut hasher = Keccak256::new();
    hasher.update(&public_key_bytes[1..]); // Skip the first byte (the prefix)
    let hash_result = hasher.finalize();

    // Take the last 20 bytes of the hash result for the Ethereum address
    let eth_address = EthAddress::from_slice(&hash_result[hash_result.len() - 20..]);

    Ok((btc_address, eth_address))
}

fn main() {
    // Example private key (hex format)
    let private_key = "4c0883a69102937d6231471b5ecb66e7f9b5a12b133dbb3a34a3b91a45618b3f"; // Replace with your own private key

    match private_key_to_addresses(private_key) {
        Ok((btc_address, eth_address)) => {
            println!("Bitcoin Address: {}", btc_address);
            println!("Ethereum Address: {:?}", eth_address); // Use `{:?}` to print full address
        }
        Err(e) => eprintln!("Error generating addresses: {}", e),
    }
}
