use api_client::{ApiClient, UnregisteredApiClient};
use minimal_ds_types::DsClientId;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    extensions::ExtensionType,
    group::config::CryptoConfig,
    key_packages::KeyPackageBuilder,
    prelude::{Capabilities, SignatureScheme},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use url::Url;

async fn register_client(identity: &str) -> ApiClient {
    // We first need an ID and a credential, as well as a signature key pair.
    let client_id = DsClientId::new(identity.as_bytes()).unwrap();
    let credential = BasicCredential::new(client_id.as_bytes().to_vec())
        .unwrap()
        .into();
    let signature_key_pair = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let credential_with_key = CredentialWithKey {
        credential,
        signature_key: signature_key_pair.public().into(),
    };

    // We can now generate KeyPackages. The backend we provide will store
    // private keys and perform cryptographic operations.
    let backend = OpenMlsRustCrypto::default();

    // The capabilities determine which (non-default) versions, ciphersuites and
    // extensions the client supports. We have to use this, because the
    // `last_resort` extension is not a default extension.
    let capabilities = Capabilities::new(
        None, // no non-default versions
        None, // no non-default cipher suites
        Some(&[ExtensionType::LastResort]),
        None, // no non-default proposal types
        None, // no non-default credentials
    );

    // Determine the MLS version and ciphersuite to use for KeyPackage
    // generation. In this case, we use the default version (v1) and ciphersuite
    // (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
    let crypto_config = CryptoConfig::default();

    // One of the KeyPackages must be a KeyPackage for use as a last resort,
    // i.e. when all other KeyPackages have been exhausted.
    let last_resort_key_package = KeyPackageBuilder::new()
        .mark_as_last_resort()
        .leaf_node_capabilities(capabilities.clone())
        .build(
            crypto_config,
            &backend,
            &signature_key_pair,
            credential_with_key.clone(),
        )
        .unwrap()
        .into();

    // Generate a number of KeyPackages to register with the DS.
    let key_packages = (0..10)
        .map(|_| {
            KeyPackageBuilder::new()
                .leaf_node_capabilities(capabilities.clone())
                .build(
                    crypto_config,
                    &backend,
                    &signature_key_pair,
                    credential_with_key.clone(),
                )
                .unwrap()
                .into()
        })
        .collect::<Vec<_>>();

    // Register the new client with the DS.
    let ds_url = Url::parse("https://ds.openmls.tech").unwrap();
    let unregistered_api_client = UnregisteredApiClient::new(ds_url);

    unregistered_api_client
        .register(key_packages.as_slice(), &last_resort_key_package)
        .await
        .unwrap()
}

#[tokio::main]
async fn main() {
    // Create a new client
    let _alice = register_client(b"alice").await;

    // Interact with the DS...
}
