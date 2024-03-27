use std::collections::HashMap;

use api_client::{ApiClient, DsGroupId, UnregisteredApiClient};
use minimal_ds_types::DsClientId;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    extensions::ExtensionType,
    framing::{
        ApplicationMessage, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent,
        ProtocolMessage,
    },
    group::{
        config::CryptoConfig, GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupCreateConfigBuilder,
        MlsGroupJoinConfig, MlsGroupJoinConfigBuilder, StagedWelcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackageBuilder,
    prelude::{Capabilities, OpenMlsProvider, SignatureScheme},
    versions::ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use url::Url;

fn build_group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfigBuilder::default()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn build_group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfigBuilder::default()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

// Helper struct to hold client information
struct Client {
    api_client: ApiClient,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
    crypto_backend: OpenMlsRustCrypto,
    groups: HashMap<DsGroupId, MlsGroup>,
}

impl Client {
    /// Access the crypto backend
    fn crypto_backend(&self) -> &OpenMlsRustCrypto {
        &self.crypto_backend
    }

    /// Access the signature key pair
    fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    /// Register a new client with the DS
    async fn register(identity: &str) -> Self {
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
        let ds_url = Url::parse("https://ds.openmls.tech/minimal-ds").unwrap();
        let unregistered_api_client = UnregisteredApiClient::new(ds_url);

        let api_client = unregistered_api_client
            .register(key_packages.as_slice(), &last_resort_key_package)
            .await
            .unwrap();

        Self {
            api_client,
            credential_with_key,
            signer: signature_key_pair,
            crypto_backend: backend,
            groups: HashMap::new(),
        }
    }

    /// Create a new group and store the group state in the client
    async fn create_group(&mut self) -> DsGroupId {
        // Sample a fresh group ID

        // Create a new MlsGroup

        // Export a group info from the the group

        // Create the group on the DS

        // Store the group locally

        // Return the group ID
        todo!()
    }

    /// Add new members to the group with the given ID
    async fn add_members_to_group(&mut self, group_id: DsGroupId, new_members: &[DsClientId]) {
        // Fetch key packages for the new members from the DS

        // Add the new members to the group locally

        // Distribute the group message through the DS

        // Merge the pending commit into the (local) group state

        // Distribute the welcome message to the new members through the DS
        todo!()
    }

    /// Fetch messages from the DS
    async fn fetch_messages(&mut self) -> Vec<MlsMessageIn> {
        todo!()
    }

    /// Process messages and return any decrypted application messages
    async fn process_messages(
        &mut self,
        messages: Vec<MlsMessageIn>,
    ) -> Vec<(DsGroupId, ApplicationMessage)> {
        // Go through all messages individually

        // Extract the message body

        // Depending on the message body, either
        // - process it through an existing group
        // - create a new group from a welcome message

        // In the case of a public or private message, process the resulting
        // `ProcessedMessage` depending on the type of message
        // - if it's a proposal, store it in the group
        // - if it's a commit, merge it into the group
        // - if it's an application message, return it

        todo!()
    }

    /// Send an application message to the group with the given ID
    async fn send_application_message(&mut self, group_id: DsGroupId, payload: &[u8]) {
        // Create an application message

        // Distribute the message through the DS
        todo!()
    }
}

#[tokio::main]
async fn main() {
    // Create a new client
    let client1_name = format!("client-{}", rand::random::<u64>());
    let mut client_1 = Client::register(&client1_name).await;

    // Create another client
    let client2_name = format!("client-{}", rand::random::<u64>());
    let mut client2 = Client::register(&client2_name).await;

    // Alice creates a group
    let group_id = client_1.create_group().await;

    println!("Part 1 done, great job!");

    // Alice adds Bob to the group
    client_1
        .add_members_to_group(group_id, &[client2.api_client.client_id()])
        .await;

    // Bob fetches messages
    let messages = client2.fetch_messages().await;

    // Bob processes messages (the returned list will be empty, as alice did not send any application messages yet)
    let _decrypted_messages = client2.process_messages(messages).await;

    println!("Part 2 done, keep up the good work!");

    // Alice sends an application message to the group
    client_1
        .send_application_message(group_id, b"Hi Bob!")
        .await;

    // Bob fetches messages again
    let messages = client2.fetch_messages().await;

    // Bob processes messages
    let mut decrypted_messages = client2.process_messages(messages).await;

    let (_group_id, application_message) = decrypted_messages.pop().unwrap();

    // Check that the message is actually correct
    assert_eq!(application_message.into_bytes(), b"Hi Bob!");

    println!("Success! You are now an MLS expert!")
}
