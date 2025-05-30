use std::mem;
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
use std::fs::OpenOptions;
use std::io;
use csv::WriterBuilder;
use std::fmt::Display;

fn csv_writer(function_name: &str, duration: Duration) -> io::Result<()> {

    // Open the CSV file in append mode
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("classic.csv")?;

    // Create a CSV writer that does not write headers
    let mut wtr = WriterBuilder::new()
        .has_headers(false)
        .from_writer(file);

    // Write the measurement (e.g., function name and duration in milliseconds)
    wtr.write_record(&[
        function_name,
        format!("{:?}", duration).as_str(),
    ])?;
    wtr.flush()?;

    Ok(())
}

pub struct KeyManager{
    ks_relayid_rsa: Option<RsaPrivateKey>,
    kp_relayid_rsa: Option<RsaPublicKey>,
    relayid_ed: Option<SigningKey>,
    ks_kyber: Option<SecretKey>,
    kp_kyber: Option<PublicKey>,
    relayid_digest:Option<[u8;20]>,
    ks_ntor: Option<ReusableSecret>,
    kp_ntor: Option<x25519_dalek::PublicKey>,
    rng: Option<ThreadRng>
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

    pub fn generate_curve_keys(&mut self) {
        // A curve25519 key used for the ntor and ntorv3 circuit extension handshakes.
        let start = Instant::now();
        let csprng = rngs::OsRng{};
        let secret_key = ReusableSecret::random_from_rng(csprng);
        let public_key = x25519_dalek::PublicKey::from(&secret_key);
        self.ks_ntor = Some(secret_key);
        self.kp_ntor = Some(public_key);
        let duration = start.elapsed();
        csv_writer("generate_ntor_keys", duration);
    }
}
pub struct ClientSide{
    node_id: [u8;20],
    key_id: x25519_dalek::PublicKey,
    client_ks: ReusableSecret,
    client_kp: x25519_dalek::PublicKey
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientData{
    node_id: [u8;20],
    key_id: x25519_dalek::PublicKey,
    client_kp: x25519_dalek::PublicKey
}
impl ClientSide {
    pub fn new(node_id: [u8;20], server_onion_key: x25519_dalek::PublicKey) -> Self {
        let mut client_key_manager = KeyManager::new();
        client_key_manager.generate_curve_keys();

        Self {
            node_id: node_id, //NODEID = ID
            key_id: server_onion_key, //KEYID(B) = B
            client_kp: client_key_manager.kp_ntor.unwrap(), //X
            client_ks: client_key_manager.ks_ntor.unwrap(), //x
        }
    }
    pub fn send_to_server(&self) -> ClientData {
        // To perform the handshake, the client needs to know an identity key digest for the server,
        // and an ntor onion key (a curve25519 public key) for that server.
        // Call the ntor onion key B.
        // This function generate a client_side handshake with content NODEID (Server identity digest, 20 bytes), KEYID (KEYID(B), 32 bytes), CLIENT_KP(X, 32 bytes))
        ClientData {
            node_id: self.node_id,
            key_id: self.key_id,
            client_kp: self.client_kp,
        }
    }

    pub fn client_ckeck(self, server_kp:x25519_dalek::PublicKey, auth:&[u8]) -> ([u8;32], [u8;32], bool) {
        let start = Instant::now();

        // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
        // EXP(a, b) = The ECDH algorithm for establishing a shared secret
        let shared_secret_y = self.client_ks.diffie_hellman(&server_kp).to_bytes(); //EXP(Y, x) -> use x25519_dalek::ReusableSecret
        let shared_secret_b = self.client_ks.diffie_hellman(&self.key_id).to_bytes(); //EXP(B, x)
        let id = &self.node_id; //ID
        let b = self.key_id.as_ref(); //B
        let protoid = "ntor-curve25519-sha256-1".as_bytes(); //PROTOID = "ntor-curve25519-sha256-1"
        let y: &[u8; 32] = server_kp.as_bytes(); //Y
        let x:&[u8; 32] = self.client_kp.as_bytes(); //X

        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(&shared_secret_y);
        secret_input.extend_from_slice(&shared_secret_b);
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
        let verify = t_verify.as_slice();

        // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(verify);
        auth_input.extend_from_slice(id);
        auth_input.extend_from_slice(b);
        auth_input.extend_from_slice(y);
        auth_input.extend_from_slice(self.client_kp.as_bytes());
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
        //assert_eq!(server_auth, client_auth);

        return if server_auth == client_auth {
            let duration = start.elapsed();
            csv_writer("ClientSide::client_ckeck", duration);
            (shared_secret_y, shared_secret_b, true)
        } else {
            let duration = start.elapsed();
            csv_writer("ClientSide::client_ckeck", duration);
            (shared_secret_y, shared_secret_b, false)
        }
    }
}

pub struct ServerSide{
    server_kp_ntor: x25519_dalek::PublicKey,
    server_ks_ntor: ReusableSecret,
    server_ks: ReusableSecret,
    server_kp: x25519_dalek::PublicKey,
    node_id: [u8;20]
}
pub struct ServerData{
    shared_secret_y: [u8;32],
    shared_secret_b: [u8;32]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerReply{
    server_kp: x25519_dalek::PublicKey,
    auth: Vec<u8>,
}
impl ServerSide{
    pub fn new(server_ks_ntor: ReusableSecret, server_kp_ntor: x25519_dalek::PublicKey, node_id: [u8;20]) -> Self{
        let mut server_key_manager = KeyManager::new();
        server_key_manager.generate_curve_keys();

        Self{
            server_ks: server_key_manager.ks_ntor.unwrap(), // y
            server_kp: server_key_manager.kp_ntor.unwrap(), // Y
            server_kp_ntor: server_kp_ntor, // B
            server_ks_ntor: server_ks_ntor, // b
            node_id: node_id, // ID
        }

    }

    pub fn send_to_client(self, client_kp: x25519_dalek::PublicKey) -> (ServerData, ServerReply) {
        let start = Instant::now();

        // The server generates a keypair of y,Y = KEYGEN(), and uses its ntor private key b to compute the server_side
        // Then the server reply with (SERVER_KP (Y, 32byets), AUTH (H(auth_input, t_mac), 32 bytes))
        // EXP(a, b) = The ECDH algorithm for establishing a shared secret
        //let start = Instant::now();
        let shared_secret_y = self.server_ks.diffie_hellman(&client_kp).to_bytes(); //EXP(X,y)
        let shared_secret_b = self.server_ks_ntor.diffie_hellman(&client_kp).to_bytes(); //EXP(X,b)
        //let shared_secret_duration = start.elapsed();
        let id = &self.node_id; // Identity key digest
        let b = self.server_kp_ntor.as_ref(); //B
        let protoid = "ntor-curve25519-sha256-1".as_bytes(); //PROTOID = "ntor-curve25519-sha256-1"
        let y:&[u8; 32] = self.server_kp.as_bytes();
        let x:&[u8; 32] = client_kp.as_bytes();

        // secrete_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(&shared_secret_y);
        secret_input.extend_from_slice(&shared_secret_b);
        secret_input.extend_from_slice(id);
        secret_input.extend_from_slice(b);
        secret_input.extend_from_slice(x);
        secret_input.extend_from_slice(y);
        secret_input.extend_from_slice(protoid);
        //println!("the secret input for server is : {:?}", secret_input);

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
        let verify = t_verify.as_slice();

        // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(verify);
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
        let server_data = ServerData{shared_secret_y, shared_secret_b};
        let server_reply = ServerReply{server_kp, auth};

        let duration = start.elapsed();
        csv_writer("ServerSide::send_to_client", duration);

        return (server_data, server_reply)
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind"); //Bind an available port
        let address = listener.local_addr().expect("Failed to get local address"); //get the assigned address

        Self {listener, address}
    }

    pub fn send_to_server(server_addr: SocketAddr, client_data: &ClientData){
        let start = Instant::now();

        // Send the client data to server node over TCP connection
        let encoded: Vec<u8> = bincode::serialize(client_data).expect("Serialization failed.");
        let mut stream = TcpStream::connect(server_addr).expect("Can't connect to server.");
        stream.write(&encoded).expect("Streaming message to server failed.");

        let duration = start.elapsed();
        csv_writer("ClientNode::sent_to_server", duration);
    }
    fn deserializing(self, mut stream: TcpStream) -> ServerReply {
        let start = Instant::now();

        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).unwrap();
        let received_data: ServerReply = bincode::deserialize(&buffer).expect("Deserialization failed.");

        let duration = start.elapsed();
        csv_writer("ClientNode::deserializing", duration);

        return received_data;
    }
    fn handle_server(self) -> Option<ServerReply> {
        let start = Instant::now();

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    //println!("Connection established!");
                    let server_reply = self.deserializing(stream);

                    let duration = start.elapsed();
                    csv_writer("ClientNode::handle_server", duration);

                    return Some(server_reply);
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);

                    let duration = start.elapsed();
                    csv_writer("ClientNode::handle_server", duration);

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
        let listener = TcpListener::bind("127.0.0.1:1024").expect("Could not bind"); //Bind an available port
        let address = listener.local_addr().expect("Failed to get local address"); //get the assigned address

        Self {listener, address}
    }

    pub fn send_to_client(client_addr: SocketAddr, server_reply: &ServerReply){
        let start = Instant::now();

        // Send the client data to server node over TCP connection
        let encoded: Vec<u8> = bincode::serialize(server_reply).expect("Serialization failed.");
        let mut stream = TcpStream::connect(client_addr).expect("Can't connect to server.");
        stream.write(&encoded).expect("Streaming message to server failed.");

        let duration = start.elapsed();
        csv_writer("ServerNode::send_to_client", duration);
    }
    fn deserializing(self, mut stream: TcpStream) -> ClientData {
        let start = Instant::now();

        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).unwrap();
        let received_data: ClientData = bincode::deserialize(&buffer).expect("Deserialization failed.");

        let duration = start.elapsed();
        csv_writer("ServerNode::deserializing", duration);

        return received_data;
    }
    fn handle_client(self) -> Option<ClientData> {
        let start = Instant::now();

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    //println!("Connection established!");
                    let client_data = self.deserializing(stream);

                    let duration = start.elapsed();
                    csv_writer("ServerNode::handle_client", duration);

                    return Some(client_data);
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);

                    let duration = start.elapsed();
                    csv_writer("ServerNode::handle_client", duration);

                    continue;
                }
            }
        }
        None
    }
}

pub struct ClassicNtorTcp{
    server_ks_ntor: Option<ReusableSecret>,
    server_kp_ntor: Option<x25519_dalek::PublicKey>,
    server_relayid_digest: Option<[u8;20]>
}

impl ClassicNtorTcp {
    pub fn new() -> Self {
        let mut server_key_manager = KeyManager::new();
        server_key_manager.generate_rsa_keys(None);
        server_key_manager.generate_curve_keys();

        Self{
            server_ks_ntor: server_key_manager.ks_ntor, //b
            server_kp_ntor: server_key_manager.kp_ntor, //B
            server_relayid_digest: server_key_manager.relayid_digest //ID
        }
    }

    pub fn ntor(self) -> (usize, usize){
        let start = Instant::now();

        let server_node = ServerNode::new();
        let client_node =  ClientNode::new();
        let client_addr = client_node.address;
        /*
        let (shared_secret_y, shared_secret_b, result) = client_node.handshake_client(self.server_relayid_digest.unwrap(), self.server_kp_ntor.unwrap(), server_node.address);
        let server_data = server_node.handshake_server(self.server_ks_ntor.unwrap(), client_addr);
        */
        let client_side = ClientSide::new(self.server_relayid_digest.unwrap(), self.server_kp_ntor.unwrap());
        let client_data = client_side.send_to_server();

        //Calculate the size of the ClientData struct
        let client_reply_size = size_of_val(&client_data);

        // Client serialize the data and send it to server over TCP connection
        ClientNode::send_to_server(server_node.address, &client_data);

        // Sever get the client data and deserialize it
        let client_data_server = server_node.handle_client().expect("couldn't unwrap client data");

        let server_side = ServerSide::new(self.server_ks_ntor.unwrap(), client_data_server.key_id, client_data_server.node_id);
        let (server_data, server_reply) = server_side.send_to_client(client_data_server.client_kp);

        // Calculate the size of the ServerData struct
        let server_reply_size = size_of_val(&server_reply);

        //Server serialize the server's reply and send it to client.
        ServerNode::send_to_client(client_addr, &server_reply);

        //Client get the server's reply and deserialize it
        let server_reply_client = client_node.handle_server().expect("couldn't unwrap server's reply");

        let (shared_secret_y, shared_secret_b, result) = client_side.client_ckeck(server_reply_client.server_kp, &server_reply_client.auth);

        // Both parties check that none of the EXP() operations produced the point at infinity.
        // [NOTE: This is an adequate replacement for checking Y for group membership, if the group is curve25519.]
        fn finalize(shared_secret_y: [u8;32], shared_secret_b: [u8;32]) -> bool{
            if shared_secret_y.iter().all(|&byte| byte == 0) && shared_secret_b.iter().all(|&byte| byte == 0) {
                return false;
            }
            else {
                return true;
            }
        }

        // Print size of the packets
        //println!("Size of client' reply in classic ntor handshake: {} bytes", size_of_clientdata);
        //println!("Size of server' reply in classic ntor handshake is: {} bytes", size_of_serverdata);

        if result{
            let server_result = finalize(server_data.shared_secret_y, server_data.shared_secret_b);
            let client_result = finalize(shared_secret_y, shared_secret_b);
            if server_result && client_result {
                //println!("Handshake was successful!")
                let duration = start.elapsed();
                csv_writer("NtorTcp::ntor", duration);

                return (client_reply_size, server_reply_size)
            }
            else {
                println!("Handshake Failed!");
                return (client_reply_size, server_reply_size)
            }

        }
        else {
            println!("Authentication Failed!");
            return (client_reply_size, server_reply_size)
        }
    }
}
