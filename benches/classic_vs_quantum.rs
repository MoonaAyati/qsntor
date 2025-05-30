use ntor::{classic_ntor, quantum_safe_ntor};
use criterion::{black_box, criterion_group, criterion_main, Criterion}; // Removed BenchmarkId, BenchmarkGroup
use std::time::Duration;

// Imports for quantum_safe_ntor benchmarks
use ntor::quantum_safe_ntor::{KeyManager as QsKeyManager, ClientSideQs, ServerSideQs};
use pqc_kyber::{PublicKey as KyberPublicKey, SecretKey as KyberSecretKey, encapsulate, decapsulate, keypair};
use rand::thread_rng;

// Removed: use ntor::classic_ntor::{KeyManager, ClientSide, ServerSide};
// Removed: use x25519_dalek::PublicKey as X25519PublicKey;
// ReusableSecret might not be directly needed if KeyManager handles its own secrets for curve keys
// use x25519_dalek::ReusableSecret;
// OsRng might not be needed if KeyManager instantiates it internally
// use rand::rngs::OsRng;
// Removed: use ntor::classic_ntor::RsaPrivateKey; // For KeyManager setup
// Removed: use rsa::RsaPublicKey; // Potentially for some setups, though KeyManager abstracts its usage

fn classic() {
    let classic_handshake = classic_ntor::ClassicNtorTcp::new();
    let (client_reply_size, server_reply_size) = classic_handshake.ntor();
}

fn quantum() {
    let quantum_handshake = quantum_safe_ntor::QuantumNtorTcp::new();
    let (client_reply_size, server_reply_size) = quantum_handshake.ntor();
}

fn bench_ntor(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntor_roup");
    group.measurement_time(Duration::from_secs(300));
    group.sample_size(2000); // Set sample size to 1000

    group.bench_function("classic_ntor", |b| b.iter(|| classic()));
    group.bench_function("quantum.ntor", |b| b.iter(|| quantum()));

    group.finish();

   let mut classic_individual_group = c.benchmark_group("classic_ntor_individual");

    // Benchmark for KeyManager::generate_curve_keys
    classic_individual_group.bench_function("classic_key_manager_generate_curve_keys", |b| {
        b.iter_with_setup(
            || {
                let mut km = classic_ntor::KeyManager::new();
                // generate_rsa_keys is needed to get relayid_digest, which might be implicitly needed by other functions
                // or if other key_manager functions are called first in real scenarios.
                km.generate_rsa_keys(Some(1024));
                km
            },
            |mut km| km.generate_curve_keys(),
        )
    });

    // Benchmark for ClientSide::new
    classic_individual_group.bench_function("classic_client_side_new", |b| {
        b.iter_with_setup(
            || {
                let mut server_km = classic_ntor::KeyManager::new();
                server_km.generate_rsa_keys(Some(1024)); // For node_id (relayid_digest)
                server_km.generate_curve_keys(); // For server_onion_key (kp_ntor)
                let node_id = server_km.relayid_digest.unwrap();
                let server_onion_key = server_km.kp_ntor.unwrap();
                (node_id, server_onion_key)
            },
            |(node_id, server_onion_key)| {
                classic_ntor::ClientSide::new(black_box(node_id), black_box(server_onion_key))
            },
        )
    });

    // Benchmark for ClientSide::client_check
    classic_individual_group.bench_function("classic_client_side_client_check", |b| {
        b.iter_with_setup(
            || {
                // Server's main ntor key (B)
                let mut server_b_km = classic_ntor::KeyManager::new();
                server_b_km.generate_rsa_keys(Some(1024)); // For node_id
                server_b_km.generate_curve_keys();
                let node_id = server_b_km.relayid_digest.unwrap();
                let server_onion_key_b = server_b_km.kp_ntor.unwrap();

                // ClientSide instance (x, X)
                let client_side = classic_ntor::ClientSide::new(node_id, server_onion_key_b);

                // Server's ephemeral key (Y) - In classic ntor, this Y is Server's public ntor key (B)
                // The client_check function expects the server's public key `kp_ntor` (B)
                // and the auth_input which is derived from H(X | Y | ID | b | g^y)
                // For the purpose of this benchmark, we need the server's public key `B` (server_onion_key_b)
                // and a dummy `auth` value. The `server_kp_y` in the original prompt seems to be a slight misunderstanding
                // of classic ntor flow. client_check uses server_onion_key (B) and auth_input.
                // The server's ephemeral key Y is part of the handshake but not directly passed to client_check.
                // client_check verifies the server's response which includes auth_input.
                // Let's assume the auth is pre-calculated/dummy for this unit benchmark.

                // The `client_check` method in the provided library snippet takes `server_pk: X25519PublicKey, auth_input: &[u8; 32]`
                // `server_pk` is `B`, the server's long-term public key.
                // `auth_input` is what the client calculates and compares against server's response.
                // For benchmarking `client_check` in isolation, we need a ClientSide instance,
                // the server's public key (B), and a dummy auth value.
                let auth = [0u8; 32]; // Dummy auth for benchmark purposes
                (client_side, server_onion_key_b, auth)
            },
            |(client_side, server_onion_key_b, auth)| {
                // The method is client_ckeck (typo in provided snippet, assuming it's client_check in actual code)
                // If the actual method name in the library is `client_ckeck`, this should be changed.
                // Assuming it's `client_check` based on common naming.
                client_side.client_ckeck(black_box(server_onion_key_b), black_box(&auth))
            },
        )
    });

    // Benchmark for ServerSide::new
    classic_individual_group.bench_function("classic_server_side_new", |b| {
        b.iter_with_setup(
            || {
                let mut server_km = classic_ntor::KeyManager::new();
                server_km.generate_rsa_keys(Some(1024)); // For node_id
                server_km.generate_curve_keys(); // For ks_ntor, kp_ntor
                let ks_ntor = server_km.ks_ntor.unwrap();
                let kp_ntor = server_km.kp_ntor.unwrap();
                let node_id = server_km.relayid_digest.unwrap();
                (ks_ntor, kp_ntor, node_id)
            },
            |(ks_ntor, kp_ntor, node_id)| {
                classic_ntor::ServerSide::new(black_box(ks_ntor), black_box(kp_ntor), black_box(node_id))
            },
        )
    });

    // Benchmark for ServerSide::send_to_client
    classic_individual_group.bench_function("classic_server_side_send_to_client", |b| {
        b.iter_with_setup(
            || {
                // Server's main ntor key (b, B)
                let mut server_b_km = classic_ntor::KeyManager::new();
                server_b_km.generate_rsa_keys(Some(1024)); // For node_id
                server_b_km.generate_curve_keys(); // For main ntor keys (b,B)

                let server_side = classic_ntor::ServerSide::new(
                    server_b_km.ks_ntor.unwrap(),
                    server_b_km.kp_ntor.unwrap(),
                    server_b_km.relayid_digest.unwrap()
                );

                // Client's ephemeral key (X) - This is the client's public key part of their ephemeral DH contribution.
                // The `send_to_client` method expects the client's public key `X`.
                let mut client_x_km = classic_ntor::KeyManager::new();
                // We only need the public part of a curve key pair for client_X_pk
                // No need to generate RSA keys for the client's ephemeral key manager.
                client_x_km.generate_curve_keys();
                let client_X_pk = client_x_km.kp_ntor.unwrap(); // This is g^x, the client's public ephemeral key
                (server_side, client_X_pk)
            },
            |(server_side, client_X_pk)| {
                server_side.send_to_client(black_box(client_X_pk))
            },
        )
    });

   classic_individual_group.finish();
   let mut quantum_individual_group = c.benchmark_group("quantum_safe_ntor_individual");

    // Benchmark for KeyManager::generate_kyber_keys
    quantum_individual_group.bench_function("qs_key_manager_generate_kyber_keys", |b| {
        b.iter_with_setup(
            || {
                let mut km = ntor::quantum_safe_ntor::KeyManager::new();
                km.generate_rsa_keys(Some(1024)); // For relayid_digest
                km
            },
            |mut km| km.generate_kyber_keys(),
        )
    });

    // Benchmark for ClientSideQs::new
    quantum_individual_group.bench_function("qs_client_side_new", |b| {
        b.iter_with_setup(
            || {
                let mut server_km = ntor::quantum_safe_ntor::KeyManager::new();
                server_km.generate_rsa_keys(Some(1024));
                server_km.generate_kyber_keys();
                let node_id = server_km.relayid_digest.unwrap();
                let server_onion_key = server_km.kp_kyber.unwrap();
                (node_id, server_onion_key)
            },
            |(node_id, server_onion_key)| {
                ntor::quantum_safe_ntor::ClientSideQs::new(black_box(node_id), black_box(server_onion_key))
            },
        )
    });

    // Benchmark for ClientSideQs::client_check
    quantum_individual_group.bench_function("qs_client_side_client_check", |b| {
        b.iter_with_setup(
            || {
                let mut server_b_km = ntor::quantum_safe_ntor::KeyManager::new();
                server_b_km.generate_rsa_keys(Some(1024));
                server_b_km.generate_kyber_keys();
                let node_id = server_b_km.relayid_digest.unwrap();
                let server_onion_key_b = server_b_km.kp_kyber.unwrap();

                let client_side_qs = ntor::quantum_safe_ntor::ClientSideQs::new(node_id, server_onion_key_b);

                let mut server_y_km = ntor::quantum_safe_ntor::KeyManager::new();
                server_y_km.generate_kyber_keys();
                let server_kp_y = server_y_km.kp_kyber.unwrap();

                let auth = [0u8; 32]; // Dummy auth
                let shared_y = [0u8; 32]; // Dummy shared secret
                let shared_b = [0u8; 32]; // Dummy shared secret
                (client_side_qs, server_kp_y, auth, shared_y, shared_b)
            },
            |(client_side_qs, server_kp_y, auth, shared_y, shared_b)| {
                client_side_qs.client_ckeck(black_box(server_kp_y), black_box(&auth), black_box(&shared_y), black_box(&shared_b))
            },
        )
    });

    // Benchmark for ServerSideQs::new
    quantum_individual_group.bench_function("qs_server_side_new", |b| {
        b.iter_with_setup(
            || {
                let mut server_km = ntor::quantum_safe_ntor::KeyManager::new();
                server_km.generate_rsa_keys(Some(1024));
                server_km.generate_kyber_keys();
                let ks_kyber = server_km.ks_kyber.unwrap();
                let kp_kyber = server_km.kp_kyber.unwrap();
                let node_id = server_km.relayid_digest.unwrap();
                (ks_kyber, kp_kyber, node_id)
            },
            |(ks_kyber, kp_kyber, node_id)| {
                ntor::quantum_safe_ntor::ServerSideQs::new(black_box(ks_kyber), black_box(kp_kyber), black_box(node_id))
            },
        )
    });

    // Benchmark for ServerSideQs::send_to_client (with encapsulation)
    quantum_individual_group.bench_function("qs_server_side_send_to_client_with_encap", |b| {
        b.iter_with_setup(
            || {
                let mut server_km_main_b = ntor::quantum_safe_ntor::KeyManager::new();
                server_km_main_b.generate_rsa_keys(Some(1024));
                server_km_main_b.generate_kyber_keys();

                let kp_kyber_b = server_km_main_b.kp_kyber.unwrap();
                let ks_kyber_b = server_km_main_b.ks_kyber.unwrap();
                let node_id = server_km_main_b.relayid_digest.unwrap();

                let server_side = ntor::quantum_safe_ntor::ServerSideQs::new(ks_kyber_b, kp_kyber_b, node_id);

                let mut client_x_km = ntor::quantum_safe_ntor::KeyManager::new();
                client_x_km.generate_kyber_keys();
                let client_kp_x = client_x_km.kp_kyber.unwrap();

                let mut temp_rng_for_y = rand::thread_rng();
                let (ciphertext_y, _shared_secret_y_client) = encapsulate(&server_side.server_kp, &mut temp_rng_for_y).unwrap();

                let mut temp_rng_for_b = rand::thread_rng();
                let (ciphertext_b, _shared_secret_b_client) = encapsulate(&server_side.server_kp_kyber, &mut temp_rng_for_b).unwrap();

                (server_side, client_kp_x, ciphertext_y, ciphertext_b)
            },
            |(server_side, client_kp_x, ciphertext_y, ciphertext_b)| {
                server_side.send_to_client(black_box(client_kp_x), black_box(&ciphertext_y), black_box(&ciphertext_b))
            },
        )
    });

   quantum_individual_group.finish();
}

criterion_group!(benches, bench_ntor);
criterion_main!(benches);