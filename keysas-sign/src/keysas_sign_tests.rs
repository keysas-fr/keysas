use ed25519_dalek::SigningKey;
use keysas_lib::keysas_key::KeysasKey;
use keysas_lib::keysas_key::KeysasPQKey;
use tempfile::NamedTempFile;

use crate::Config;
use crate::generate_signing_keypair;

#[test]
#[cfg_attr(miri, ignore)]
fn test_generate_signing_keypair() {
    // Generate temporay path to save the keys

    use pkcs8::der::DecodePem;
    use x509_cert::request::CertReq;
    let path_cl = NamedTempFile::new().unwrap().into_temp_path();
    let file_cl = path_cl.to_str().unwrap();
    let path_pq = NamedTempFile::new().unwrap().into_temp_path();
    let file_pq = path_pq.to_str().unwrap();

    // Create mock Config
    let config = Config {
        generate: true,
        load: false,
        name: String::from("Keysas_station"),
        cert_type: String::from(""),
        cert: String::from(""),
    };

    // Generate the key and get the resulting CSRs
    let csrs = generate_signing_keypair(&config, file_cl, file_pq, "Test").unwrap();
    println!("CSR: {:?}", csrs);

    // Test the private keys by loading them
    SigningKey::load_keys(&path_cl, "Test").unwrap();
    KeysasPQKey::load_keys(&path_pq, "Test").unwrap();

    // Test the CSRs by reconstructing them from the function result
    let mut csr = csrs.split('|');
    let csr_cl = csr.next().unwrap();
    let csr_pq = csr.remainder().unwrap();
    CertReq::from_pem(csr_cl).unwrap();
    CertReq::from_pem(csr_pq).unwrap();
}
