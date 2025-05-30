use std::time::{Duration, Instant};
use ntor::classic_ntor;
use ntor::quantum_safe_ntor;
use std::fs::OpenOptions;
use std::io;
use csv::WriterBuilder;
use std::fmt::Display;

fn main(){
    fn csv_writer(file_name: &str, function_name: &str, duration: u128) -> io::Result<()> {

        // Open the CSV file in append mode
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)?;

        // Create a CSV writer that does not write headers
        let mut wtr = WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);

        // Write the measurement (e.g., function name and duration in milliseconds)
        wtr.write_record(&[
            function_name,
            format!("{}", duration).as_str(),
        ])?;
        wtr.flush()?;

        Ok(())
    }

    fn classic() {
        println!("Classic: ");
        let start = Instant::now();

        let classic_handshake = classic_ntor::ClassicNtorTcp::new();
        let (client_reply_size, server_reply_size) = classic_handshake.ntor();

        let duration = start.elapsed().as_nanos();
        let _ = csv_writer("classic.csv","Classic_ntor", duration);
        //println!("Client's reply size: {}\nServer's reply size: {}", client_reply_size, server_reply_size);
        println!("Duration: {}", duration);
    }

    fn quantum() {
        println!("Quantum: ");
        let start = Instant::now();

        let quantum_handshake = quantum_safe_ntor::QuantumNtorTcp::new();
        let (_client_reply_size, _server_reply_size) = quantum_handshake.ntor();

        let duration = start.elapsed().as_nanos();
        csv_writer("quantum.csv","Quantum_ntor", duration);
        //println!("Client's reply size: {}\nServer's reply size: {}", client_reply_size, server_reply_size);
        println!("Duration: {}", duration);
    }

    classic();
    quantum();

}
