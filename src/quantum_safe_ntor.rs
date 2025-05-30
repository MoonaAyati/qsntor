use std::mem::size_of_val;
// std::io will be removed if OpenOptions and WriterBuilder are its only users here.
// Assuming Read/Write might be used by TcpStream, so keeping them for now.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use pqc_kyber::*;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use rsa::pkcs1::EncodeRsaPublicKey;
use hmac::{Hmac, Mac};
use sha1::{Sha1, Digest};
use sha2::Sha256;
use rand::rngs;
use ed25519_dalek::SigningKey;
use rand::rngs::ThreadRng;
use std::time::{Duration, Instant};
use x25519_dalek::ReusableSecret;
use serde::{Deserialize, Serialize};
use bincode;
use serde_big_array::BigArray;
// Removed: use std::fs::OpenOptions;
use std::io::{self}; // If io is only for csv_writer, it can be removed or reduced.
// Removed: use csv::WriterBuilder;


pub struct KeyManager{
    ks_relayid_rsa: Option<RsaPrivateKey>,
    kp_relayid_rsa: Option<RsaPublicKey>,
    relayid_ed: Option<SigningKey>,
    pub ks_kyber: Option<SecretKey>,
    pub kp_kyber: Option<PublicKey>,
    pub relayid_digest:Option<[u8;20]>,
    ks_ntor: Option<ReusableSecret>, // Not requested to be public for quantum benchmarks
    kp_ntor: Option<x25519_dalek::PublicKey>, // Not requested to be public for quantum benchmarks
    pub rng: Option<ThreadRng>
}

impl KeyManager{
    pub fn new() -> Self {
        Self {
            ks_relayid_rsa: None,
            kp_relayid_rsa: None,
            relayid_ed: None,
            ks_kyber: None,
            kp_kyber: None,
            relayid_digest: None,
            ks_ntor: None,
            kp_ntor: None,
            rng: None

        }
    }

    pub fn generate_kyber_keys(&mut self) {
        let start = Instant::now();
        let mut rng = rand::thread_rng();
        let kyber_key_pair = keypair(&mut rng).expect("Failed to generate kyber keypair");
        self.ks_kyber = Some(kyber_key_pair.secret);
        self.kp_kyber = Some(kyber_key_pair.public);
        self.rng = Some(rng);
        let duration = start.elapsed();
        // Removed: csv_writer("generate_ntor_keys", duration);
    }

    pub fn generate_ed_keys(&mut self) {

        let mut csprng = rngs::OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        self.relayid_ed = Some(signing_key);
    }

    pub fn generate_rsa_keys(&mut self, key_size: Option<usize>) {
        let mut rng = rand::thread_rng();
        let bits = key_size.unwrap_or(1024);
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        self.ks_relayid_rsa = Some(private_key);
        self.kp_relayid_rsa = Some(public_key.clone());


        // Here we calculate the key digest which later use in ntor handshake
        // When we refer to "the hash of a public key", unless otherwise specified,
        // we mean the SHA-1 hash of the DER encoding of an ASN.1 RSA public key (as specified in PKCS.1).
        let modulus = public_key.n().clone();
        let exponent = BigUint::from(65537u32);

        //ASM.1 version of RSA
        let rsa_public_key = RsaPublicKey::new(modulus, exponent).expect("Failed to create RSA public key");

        // Encode the RSA public key to DER format
        let der_encoding = rsa_public_key.to_pkcs1_der().expect("Failed to encode to DER");
        //println!("DER encoded public key: {:?}", der_encoding);

        // Assuming &Document can be converted to &[u8]
        let der_encoding_bytes: &[u8] = &der_encoding.as_bytes();

        let mut hasher = Sha1::new();
        hasher.update(&der_encoding_bytes);
        let result = hasher.finalize();
        let relayid_digest: [u8; 20] = result.as_slice().try_into().expect("Failed to convert shared_secret_y to array");
        self.relayid_digest = Some(relayid_digest);
    }
}
pub struct ClientSideQs {
    node_id: [u8;20],
    key_id: PublicKey,
    client_ks: SecretKey,
    client_kp: PublicKey
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientReplyQs {
    #[serde(with = "BigArray")]
    node_id: [u8;20],
    #[serde(with = "BigArray")]
    key_id: PublicKey,
    #[serde(with = "BigArray")]
    client_kp: PublicKey
}

impl ClientSideQs{
    pub fn new(node_id: [u8;20], server_onion_key: PublicKey) -> Self {
        let mut client_key_manager = KeyManager::new();
        client_key_manager.generate_kyber_keys();

        Self {
            node_id, //NODEID
            key_id: server_onion_key, //KEYID(B) = B
            client_kp: client_key_manager.kp_kyber.unwrap(), //X
            client_ks: client_key_manager.ks_kyber.unwrap(), //x
        }
    }
    pub fn send_to_server(&self) -> ClientReplyQs {
        // To perform the handshake, the client needs to know an identity key digest for the server,
        // and an ntor onion key (a curve25519 public key) for that server.
        // Call the ntor onion key B.
        // This function generate a client_side handshake with content NODEID (Server identity digest, 20 bytes), KEYID (KEYID(B), 32 bytes), CLIENT_KP(X, 32 bytes))
        ClientReplyQs {
            node_id: self.node_id.clone(),
            key_id: self.key_id.clone(),
            client_kp: self.client_kp.clone()
        }
    }
    pub fn client_ckeck(self, server_kp:PublicKey, auth:&[u8], shared_y: &[u8;32], shared_b: &[u8;32]) -> ([u8;32], [u8;32], bool) {
        let start = Instant::now();

        let shared_secret_y = shared_y;
        let shared_secret_b = shared_b;
        let x = self.client_kp.as_ref(); //X
        let id = &self.node_id; //ID
        let b = self.key_id.as_ref();
        let protoid = "ntor-curve25519-sha256-1".as_bytes(); //PROTOID = "ntor-curve25519-sha256-1"
        let y = server_kp.as_ref();

        // secrete_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(shared_secret_y);
        secret_input.extend_from_slice(shared_secret_b);
        secret_input.extend_from_slice(id);
        secret_input.extend_from_slice(b);
        secret_input.extend_from_slice(x);
        secret_input.extend_from_slice(y);
        secret_input.extend_from_slice(protoid);

        // KEY_SEED = H(secret_input, t_key)
        // t_key = PROTOID | ":key_extract"
        // The output length of HMAC-SHA256 is 32 bytes
        type HmacSha256 = Hmac<Sha256>;
        let t_key = "ntor-curve25519-sha256-1".to_owned() + ":key_extract";
        let mut hasher = HmacSha256::new_from_slice(t_key.as_bytes()).expect("HMAC can take key of any size");
        hasher.update(&secret_input);
        let _key_seed = hasher.finalize();

        // verify = H(secret_input, t_verify)
        // t_verify  = PROTOID | ":verify"
        let t_verify = "ntor-curve25519-sha256-1".to_owned() + ":verify";
        let mut hasher = HmacSha256::new_from_slice(t_verify.as_bytes()).expect("HMAC can take key of any size");
        hasher.update(&secret_input);
        let result = hasher.finalize();
        let t_verify = result.into_bytes();
        let verify= t_verify.as_ref();

        // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(verify);
        auth_input.extend_from_slice(id);
        auth_input.extend_from_slice(b);
        auth_input.extend_from_slice(y);
        auth_input.extend_from_slice(x);
        auth_input.extend_from_slice(protoid);
        auth_input.extend_from_slice(("Server").as_bytes());

        // The client verifies that AUTH == H(auth_input, t_mac) -> 32 bytes
        // t_mac = PROTOID | ":mac"
        let t_mac = "ntor-curve25519-sha256-1".to_owned() + ":mac";
        let mut hasher = HmacSha256::new_from_slice(t_mac.as_bytes()).expect("HMAC can take key of any size");
        hasher.update(&auth_input);
        let result = hasher.finalize();
        let t_client_auth = result.into_bytes();
        let client_auth = t_client_auth.as_slice();
        let server_auth = auth;
        //assert_eq!(auth, client_auth);

        return if server_auth == client_auth {
            let duration = start.elapsed();
            // Removed: csv_writer("ClientSide::client_ckeck", duration);
            (*shared_secret_y, *shared_secret_b, true)
        } else {
            let duration = start.elapsed();
            // Removed: csv_writer("ClientSide::client_ckeck", duration);
            (*shared_secret_y,*shared_secret_b,false)
        }
    }
}
pub struct ServerSideQs{
    pub server_kp_kyber: PublicKey, // Made public
    server_ks_kyber: SecretKey,
    server_rng: ThreadRng, // server_rng is not directly used by benchmarks, but by ServerSideQs internal logic
    server_ks: SecretKey,
    pub server_kp: PublicKey, // Made public
    node_id: [u8;20]
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerDataQs{
    shared_secret_y: [u8;32],
    shared_secret_b: [u8;32]
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerReplyQs{
    #[serde(with = "BigArray")]
    server_kp: PublicKey,
    auth: Vec<u8>,
}

impl ServerSideQs{
    pub fn new(server_ks_kyber: SecretKey, server_kp_kyber: PublicKey, node_id: [u8;20]) -> Self{
        let mut server_key_manager = KeyManager::new();
        server_key_manager.generate_kyber_keys();

        Self{
            server_ks: server_key_manager.ks_kyber.unwrap(), // y
            server_kp: server_key_manager.kp_kyber.unwrap(),
            server_rng: server_key_manager.rng.unwrap(),// Y
            server_kp_kyber: server_kp_kyber, // B
            server_ks_kyber: server_ks_kyber, // b
            node_id: node_id, // ID
        }

    }
    pub fn send_to_client(self, client_kp: PublicKey, ciphertext_y: &[u8], ciphertext_b: &[u8]) -> (ServerDataQs, ServerReplyQs) {
        let start = Instant::now();

        // The server generates a keypair of y,Y = KEYGEN(), and uses its ntor private key b to compute the server_side
        // Then the server reply with (SERVER_KP (Y, 32byets), AUTH (H(auth_input, t_mac), 32 bytes))
        let x = client_kp.as_ref(); //X
        // EXP(a, b) = The ECDH algorithm for establishing a shared secret
        let shared_secret_y_server = decapsulate(ciphertext_y, &self.server_ks).expect("Decapsulation failed!"); //EXP(X,y)
        let shared_secret_b_server = decapsulate(ciphertext_b, &self.server_ks_kyber).expect("Decapsulation failed!"); //EXP(X,b)
        let id = &self.node_id; // Identity key digest
        let protoid = "ntor-curve25519-sha256-1".as_bytes(); //PROTOID = "ntor-curve25519-sha256-1"
        let y = self.server_kp.as_ref();
        let b = self.server_kp_kyber.as_ref();

        // secrete_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(&shared_secret_y_server);
        secret_input.extend_from_slice(&shared_secret_b_server);
        secret_input.extend_from_slice(id);
        secret_input.extend_from_slice(b);
        secret_input.extend_from_slice(x);
        secret_input.extend_from_slice(y);
        secret_input.extend_from_slice(protoid);

        // KEY_SEED = H(secret_input, t_key)
        // t_key = PROTOID | ":key_extract"
        // The output length of HMAC-SHA256 is 32 bytes
        type HmacSha256 = Hmac<Sha256>;
        let t_key = "ntor-curve25519-sha256-1".to_owned() + ":key_extract";
        let mut hasher = HmacSha256::new_from_slice(t_key.as_bytes()).expect("HMAC can take key of any size");
        hasher.update(&secret_input);
        let _key_seed = hasher.finalize();

        // verify = H(secret_input, t_verify)
        // t_verify  = PROTOID | ":verify"
        let t_verify = "ntor-curve25519-sha256-1".to_owned() + ":verify";
        let mut hasher = HmacSha256::new_from_slice(t_verify.as_bytes()).expect("HMAC can take key of any size");
        hasher.update(&secret_input);
        let result = hasher.finalize();
        let verify = result.into_bytes();

        // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(id);
        auth_input.extend_from_slice(b);
        auth_input.extend_from_slice(y);
        auth_input.extend_from_slice(x);
        auth_input.extend_from_slice(protoid);
        auth_input.extend_from_slice(("Server").as_bytes());

        // Server answer with SERVER_KP and AUTH
        // SERVER_KP = Y 32bytes
        // AUTH = H(auth_input, t_mac) 32 bytes
        // t_mac = PROTOID | ":mac"
        let t_mac = "ntor-curve25519-sha256-1".to_owned() + ":mac";
        let mut hasher = HmacSha256::new_from_slice(t_mac.as_bytes()).expect("HMAC can take key of any size");
        hasher.update(&auth_input);
        let result = hasher.finalize();
        let auth = result.into_bytes().to_vec();

        let server_kp = self.server_kp;
        let server_reply_qs = ServerReplyQs {
            server_kp,
            auth,
        };

        let server_data_qs = ServerDataQs{
            shared_secret_y: shared_secret_y_server,
            shared_secret_b: shared_secret_b_server,
        };

        let duration = start.elapsed();
        // Removed: csv_writer("ServerSide::send_to_client", duration);

        return (server_data_qs, server_reply_qs)
    }
}

pub struct ClientNode{
    listener: TcpListener,
    address: SocketAddr
}

impl ClientNode{
    // This class implement client socket and send data over TCP connection to server.
    // It serialize ClientData type.
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:1024").expect("Could not bind"); //Bind an available port
        let address = listener.local_addr().expect("Failed to get local address"); //get the assigned address

        Self { listener, address}
    }
    pub fn send_to_server_qs(server_addr: SocketAddr, client_data: &ClientReplyQs){
        let start = Instant::now();

        // Send the client data to server node over TCP connection
        let encoded: Vec<u8> = bincode::serialize(client_data).expect("Serialization failed.");
        let mut stream = TcpStream::connect(server_addr).expect("Can't connect to server.");
        stream.write(&encoded).expect("Streaming message to server failed.");

        let duration = start.elapsed();
        // Removed: csv_writer("ClientNode::sent_to_server", duration);
    }
    fn deserializing_qs(self, mut stream: TcpStream) -> ServerReplyQs {
        let start = Instant::now();

        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).unwrap();
        let received_data: ServerReplyQs = bincode::deserialize(&buffer).expect("Deserialization failed.");

        let duration = start.elapsed();
        // Removed: csv_writer("ClientNode::deserializing", duration);

        return received_data;
    }
    fn handle_server_qs(self) -> Option<ServerReplyQs> {
        let start = Instant::now();

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    //println!("Connection established!");
                    let server_reply = self.deserializing_qs(stream);

                    let duration = start.elapsed();
                    // Removed: csv_writer("ClientNode::handle_server", duration);

                    return Some(server_reply);
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);

                    let duration = start.elapsed();
                    // Removed: csv_writer("ClientNode::handle_server", duration);

                    continue;
                }
            }
        }
        None
    }
}

pub struct ServerNode{
    listener: TcpListener,
    address: SocketAddr
}

impl ServerNode {
    // This class implement the server socket and handle the data send by client.
    // It diserialize the ClientData type and return it as an output.
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind"); //Bind an available port
        let address = listener.local_addr().expect("Failed to get local address"); //get the assigned address

        Self { listener, address }
    }
    pub fn send_to_client_qs(client_addr: SocketAddr, server_reply: &ServerReplyQs){
        let start = Instant::now();

        // Send the client data to server node over TCP connection
        let encoded: Vec<u8> = bincode::serialize(server_reply).expect("Serialization failed.");
        let mut stream = TcpStream::connect(client_addr).expect("Can't connect to server.");
        stream.write(&encoded).expect("Streaming message to server failed.");

        let duration = start.elapsed();
        // Removed: csv_writer("ServerNode::send_to_client", duration);
    }
    fn deserializing_qs(self, mut stream: TcpStream) -> ClientReplyQs {
        let start = Instant::now();

        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).unwrap();
        let received_data = bincode::deserialize(&buffer).expect("Deserialization failed.");

        let duration = start.elapsed();
        // Removed: csv_writer("ServerNode::deserializing", duration);

        return received_data;
    }
    fn handle_client_qs(self) -> Option<ClientReplyQs> {
        let start = Instant::now();

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    //println!("Connection established!");
                    let client_data = self.deserializing_qs(stream);

                    let duration = start.elapsed();
                    // Removed: csv_writer("ServerNode::handle_client", duration);

                    return Some(client_data);
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);

                    let duration = start.elapsed();
                    // Removed: csv_writer("ServerNode::handle_client", duration);

                    continue;
                }
            }
        }
        None
    }
}
pub struct QuantumNtorTcp{
    server_kp_kyber: Option<PublicKey>,
    server_ks_kyber: Option<SecretKey>,
    server_rng: ThreadRng,
    server_relayid_digest: Option<[u8;20]>
}

impl QuantumNtorTcp {
    pub fn new() -> Self{
        let mut server_key_manager = KeyManager::new();
        server_key_manager.generate_rsa_keys(None);
        server_key_manager.generate_kyber_keys();

        Self{
            server_ks_kyber: server_key_manager.ks_kyber,
            server_kp_kyber: server_key_manager.kp_kyber,
            server_rng: server_key_manager.rng.unwrap(),
            server_relayid_digest: server_key_manager.relayid_digest
        }
    }
    pub fn ntor(mut self) -> (usize, usize){
        let start = Instant::now();

        let server_node = ServerNode::new();
        let client_node =  ClientNode::new();
        let client_addr = client_node.address;

        let client_side = ClientSideQs::new(self.server_relayid_digest.unwrap(), self.server_kp_kyber.unwrap());
        let client_data = client_side.send_to_server();

        //Calculate the size of the ClientData struct
        let client_reply_size = size_of_val(&client_data);

        // Client serialize the data and send it to server over TCP connection
        ClientNode::send_to_server_qs(server_node.address, &client_data);

        // Sever get the client data and deserialize it
        let client_data_server = server_node.handle_client_qs().expect("couldn't unwrap client data");
        let mut server_side = ServerSideQs::new(self.server_ks_kyber.unwrap(), client_data_server.key_id, client_data_server.node_id);
        let (ciphertext_y, shared_y) = encapsulate(&server_side.server_kp, &mut server_side.server_rng).unwrap();//EXP(Y,x)
        let (ciphertext_b, shared_b) = encapsulate(&self.server_kp_kyber.unwrap(), &mut self.server_rng).unwrap(); //EXP(B,x)
        let (server_data_qs, server_reply_qs) = server_side.send_to_client(client_data_server.client_kp, &ciphertext_y, &ciphertext_b);

        //Calculate the size of the ServerData struct
        let server_reply_size = size_of_val(&server_reply_qs);

        //Server serialize the server's reply and send it to client.
        ServerNode::send_to_client_qs(client_addr, &server_reply_qs);

        //Client get the server's reply and deserialize it
        let server_reply_client = client_node.handle_server_qs().expect("couldn't unwrap server's reply");

        let (_shared_y, _shared_b, client_checked) = client_side.client_ckeck(server_reply_client.server_kp, &server_reply_client.auth, &shared_y, &shared_b);

        // Both parties check that none of the EXP() operations produced the point at infinity.
        // [NOTE: This is an adequate replacement for checking Y for group membership, if the group is curve25519.]
        fn finalize(shared_secret_y: &[u8;32], shared_secret_b: &[u8;32]) -> bool{
            return if shared_secret_y.iter().all(|&byte| byte == 0) && shared_secret_b.iter().all(|&byte| byte == 0) {
                false
            } else {
                true
            }
        }

        // Print the packet sizes
        //println!("Size of client' reply in quantum-safe ntor handshake is: {} bytes", size_of_clientdata);
        //println!("Size of server's reply in quantum-safe ntor handshake is: {} bytes", size_of_serverdata);

        if client_checked{
            let server_result = finalize(&server_data_qs.shared_secret_y, &server_data_qs.shared_secret_b);
            let client_result = finalize(&shared_y, &shared_b);
            if server_result && client_result {
                //println!("Handshake was successful!")
                let duration = start.elapsed();
                // Removed: csv_writer("NtorTcp::ntor", duration);

                return (client_reply_size, server_reply_size)
            }
            else {
                println!("Handshake Failed!");
                return (client_reply_size, server_reply_size)
            }
        }
        else {
            println!("Authentication Failed");
            return (client_reply_size, server_reply_size)
        }

    }

}
