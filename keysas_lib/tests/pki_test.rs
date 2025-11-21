use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use hex_literal::hex;
use keysas_lib::certificate_field::CertificateFields;
use keysas_lib::certificate_field::validate_signing_certificate;
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use keysas_lib::keysas_key::KeysasKey;
use keysas_lib::keysas_key::KeysasPQKey;
use oqs::sig::Algorithm;
use oqs::sig::Sig;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::LineEnding;
use pkcs8::PrivateKeyInfo;
use pkcs8::der::Any;
use pkcs8::der::Encode;
use pkcs8::der::asn1::BitString;
use pkcs8::pkcs5::pbes2;
use pkcs8::spki::AlgorithmIdentifier;
use rand_dl::rngs::OsRng;
use std::fs::read;
use tempfile::{NamedTempFile, tempdir};
use x509_cert::name::RdnSequence;
use x509_cert::spki::ObjectIdentifier;

#[cfg(test)]

const PASSWORD: &[u8] = b"hunter42";

#[test]
#[cfg_attr(miri, ignore)]
fn test_pkcs8_decrypt_der() {
    let cipher: &[u8] = include_bytes!("./ed25519-encpriv-aes256-scrypt.der");
    let plain: &[u8] = include_bytes!("./ed25519-priv-pkcs8v1.der");

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher).unwrap();

    let pk = enc_pk.decrypt(PASSWORD).unwrap();

    assert_eq!(pk.as_bytes(), plain);

    println!(
        "Secret document - length: {:?}, content: {:?}",
        pk.len(),
        pk.as_bytes()
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_pkcs8_create_and_decrypt_der() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = SigningKey::generate(&mut csprng);

    println!(
        "Test DER private only - Private key: {:?}",
        &keypair.to_bytes()
    );
    println!(
        "Test DER private only  - Public key: {:?}",
        &keypair.verifying_key().to_bytes()
    );

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    let salt = hex!("79d982e70df91a88");
    let iv = hex!("b2d02d78b2efd9dff694cf8e0af40925");

    let params = pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &salt,
        &iv,
    )
    .unwrap();

    let oid = ObjectIdentifier::new("1.3.101.112").unwrap();

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: oid,
            parameters: None,
        },
        private_key: &keypair.to_bytes(),
        public_key: None,
    };

    let pk_encrypted = pk_info.encrypt_with_params(params, PASSWORD).unwrap();

    pk_encrypted.write_der_file(&path).unwrap();

    // Load key from file
    let cipher = read(&path).unwrap();

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher.as_slice()).unwrap();

    let sd = enc_pk.decrypt(PASSWORD).unwrap();
    println!(
        "Test DER private only  - Secret document - length: {:?}, content: {:?}",
        sd.len(),
        sd.as_bytes()
    );

    let pk: PrivateKeyInfo = sd.decode_msg().unwrap();
    println!(
        "Test DER private only  - Private key - content: {:?}",
        pk.private_key
    );

    assert_eq!(pk.private_key, keypair.to_bytes());
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_pkcs8_create_and_decrypt_with_public_der() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = SigningKey::generate(&mut csprng);

    println!(
        "Test DER with public - Private key: {:?}",
        &keypair.to_bytes()
    );
    println!(
        "Test DER with public - Public key: {:?}",
        &keypair.verifying_key().to_bytes()
    );

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    let salt = hex!("79d982e70df91a88");
    let iv = hex!("b2d02d78b2efd9dff694cf8e0af40925");

    let params = pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &salt,
        &iv,
    )
    .unwrap();

    let oid = ObjectIdentifier::new("1.3.101.112").unwrap();

    let pub_value = keypair.verifying_key().to_bytes();

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: oid,
            parameters: None,
        },
        private_key: &keypair.to_bytes(),
        public_key: Some(&pub_value),
    };

    let pk_encrypted = pk_info.encrypt_with_params(params, PASSWORD).unwrap();

    pk_encrypted.write_der_file(&path).unwrap();

    // Load key from file
    let cipher = read(&path).unwrap();

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher.as_slice()).unwrap();

    let sd = enc_pk.decrypt(PASSWORD).unwrap();
    println!(
        "Test DER with public - Secret document - length: {:?}, content: {:?}",
        sd.len(),
        sd.as_bytes()
    );

    let pk: PrivateKeyInfo = sd.decode_msg().unwrap();
    println!(
        "Test DER with public - Private key - content: {:?}",
        pk.private_key
    );
    println!(
        "Test DER with public - Public key - content: {:?}",
        pk.public_key
    );

    assert_eq!(pk.private_key, keypair.to_bytes());
    assert_eq!(pk.public_key.unwrap(), keypair.verifying_key().to_bytes());
}

#[test]
fn test_generate_csr_ed25519() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = SigningKey::generate(&mut csprng);

    // Generate a CSR
    let subject = RdnSequence::default();
    let csr = keypair.generate_csr(&subject).unwrap();

    // Test the CSR signature
    let info = csr.info.to_der().unwrap();
    let signature = keypair.try_sign(&info).unwrap();

    assert_eq!(
        csr.signature,
        BitString::from_bytes(&signature.to_bytes()).unwrap()
    );

    // Test CSR signing algorithm
    let ed25519_oid = ObjectIdentifier::new("1.3.101.112").unwrap();
    let ref_algo: AlgorithmIdentifier<Any> = AlgorithmIdentifier {
        oid: ed25519_oid,
        parameters: None,
    };
    assert_eq!(csr.algorithm, ref_algo);

    // Test CSR Version number
    assert_eq!(csr.info.version, x509_cert::request::Version::V1);

    // Test CSR subject name
    assert_eq!(csr.info.subject, subject);

    // Test CSR public key value
    assert_eq!(
        csr.info.public_key.subject_public_key,
        BitString::from_bytes(&keypair.verifying_key().to_bytes()).unwrap()
    );
    assert_eq!(csr.info.public_key.algorithm, ref_algo);

    // Test CSR attributes
    // The CSR must not contain any attribute
    assert_eq!(csr.info.attributes.len(), 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_generate_csr_mldsa() {
    // Create the root CA ML-DSA87 key pair
    oqs::init();
    let pq_scheme = Sig::new(Algorithm::MlDsa87).unwrap();
    let (pk, sk) = pq_scheme.keypair().unwrap();
    let keypair = KeysasPQKey {
        private_key: sk,
        public_key: pk.clone(),
    };

    // Generate a CSR
    let subject = RdnSequence::default();
    let csr = keypair.generate_csr(&subject).unwrap();

    // Test the CSR signature
    match pq_scheme.verify(
        &csr.info.to_der().unwrap(),
        pq_scheme
            .signature_from_bytes(csr.signature.as_bytes().unwrap())
            .unwrap(),
        &keypair.public_key,
    ) {
        Ok(_) => assert!(true),
        Err(e) => assert!(false, "{}", e),
    }

    // Test CSR signing algorithm
    let mldsa_oid = ObjectIdentifier::new("2.16.840.1.101.3.4.3.19").unwrap();
    let ref_algo: AlgorithmIdentifier<Any> = AlgorithmIdentifier {
        oid: mldsa_oid,
        parameters: None,
    };
    assert_eq!(csr.algorithm, ref_algo);

    // Test CSR Version number
    assert_eq!(csr.info.version, x509_cert::request::Version::V1);

    // Test CSR subject name
    assert_eq!(csr.info.subject, subject);

    // Test CSR public key value
    assert_eq!(
        csr.info.public_key.subject_public_key,
        BitString::from_bytes(&keypair.public_key.clone().into_vec()).unwrap()
    );
    assert_eq!(csr.info.public_key.algorithm, ref_algo);

    // Test CSR attributes
    // The CSR must not contain any attribute
    assert_eq!(csr.info.attributes.len(), 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_save_and_load_ed25519() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = SigningKey::generate(&mut csprng);

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    // Save the keypair
    keypair.save_keys(&path, &String::from("Test")).unwrap();

    // Load the keypair
    let loaded = SigningKey::load_keys(&path, &String::from("Test")).unwrap();

    assert_eq!(loaded.to_bytes(), keypair.to_bytes());
    assert_eq!(
        loaded.verifying_key().to_bytes(),
        keypair.verifying_key().to_bytes()
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_save_and_load_mldsa() {
    // Create the root CA ML_DSA87 key pair
    oqs::init();
    let pq_scheme = Sig::new(Algorithm::MlDsa87).unwrap();
    let (pk, sk) = pq_scheme.keypair().unwrap();
    let keypair = KeysasPQKey {
        private_key: sk,
        public_key: pk.clone(),
    };

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    // Save the keypair
    keypair.save_keys(&path, &String::from("Test")).unwrap();

    // Load the keypair
    let loaded = KeysasPQKey::load_keys(&path, &String::from("Test")).unwrap();

    assert_eq!(
        loaded.private_key.into_vec(),
        keypair.private_key.into_vec()
    );
    assert_eq!(loaded.public_key.into_vec(), keypair.public_key.into_vec());
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_save_and_load_hybrid_signature() {
    use pkcs8::der::EncodePem;
    use std::path::Path;
    // Create a random keypair
    let certif_test = CertificateFields::from_fields(
        Some("org_name"),
        Some("org_unit"),
        Some("fr"),
        Some("common_name"),
        Some("333"),
    )
    .unwrap();

    let hybrid_keypair = HybridKeyPair::generate_root(&certif_test).unwrap();

    // Store the key as DER in PKCS8
    //let file = NamedTempDirectory::new().unwrap()
    //let path = file.into_temp_path();
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Save the keypair
    hybrid_keypair
        .save("test", &path, &path, &String::from("Test"))
        .unwrap();

    // Load the keypair
    let loaded_hybrid_keypair =
        HybridKeyPair::load("test", &path, &path, Path::new("/"), &String::from("Test")).unwrap();

    assert_eq!(
        loaded_hybrid_keypair.classic.to_bytes(),
        hybrid_keypair.classic.to_bytes()
    );
    assert_eq!(
        loaded_hybrid_keypair.pq.private_key,
        hybrid_keypair.pq.private_key
    );
    assert_eq!(
        validate_signing_certificate(
            &hybrid_keypair.classic_cert.to_pem(LineEnding::LF).unwrap(),
            Some(&hybrid_keypair.classic_cert),
        )
        .is_ok(),
        true
    );

    println!("Root signature is verified !\n");
    let subject = RdnSequence::default();
    let app_hybrid_keypair =
        HybridKeyPair::generate_signed_keypair(&hybrid_keypair, &subject, &certif_test, true)
            .unwrap();
    //app_hybrid_keypair
    //    .save("test-app", &path, &path, &String::from("App"))
    //    .unwrap();
    println!("Now verifying application (usb/station) signature...\n");
    assert_eq!(
        validate_signing_certificate(
            &app_hybrid_keypair
                .classic_cert
                .to_pem(LineEnding::LF)
                .unwrap(),
            Some(&hybrid_keypair.classic_cert),
        )
        .is_ok(),
        true
    );
    assert_eq!(
        validate_signing_certificate(
            &app_hybrid_keypair.pq_cert.to_pem(LineEnding::LF).unwrap(),
            Some(&hybrid_keypair.pq_cert),
        )
        .is_ok(),
        true
    );
    println!("Application signature is verified !\n");
}
