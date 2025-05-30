use std::time::Instant; // Duration removed
use ntor::classic_ntor;
use ntor::quantum_safe_ntor;
// OpenOptions, io, WriterBuilder, Display removed

fn main(){
    // csv_writer function removed

    fn classic() {
        println!("Classic: ");
        let start = Instant::now();

        let classic_handshake = classic_ntor::ClassicNtorTcp::new();
        let (_client_reply_size, _server_reply_size) = classic_handshake.ntor(); // Underscores added

        let duration = start.elapsed().as_nanos();
        // csv_writer call removed
        //println!("Client's reply size: {}\nServer's reply size: {}", client_reply_size, server_reply_size);
        println!("Duration: {}", duration);
    }

    fn quantum() {
        println!("Quantum: ");
        let start = Instant::now();

        let quantum_handshake = quantum_safe_ntor::QuantumNtorTcp::new();
        let (_client_reply_size, _server_reply_size) = quantum_handshake.ntor();

        let duration = start.elapsed().as_nanos();
        // csv_writer call removed
        //println!("Client's reply size: {}\nServer's reply size: {}", client_reply_size, server_reply_size);
        println!("Duration: {}", duration);
    }

    classic();
    quantum();

}
