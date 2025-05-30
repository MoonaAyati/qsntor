use ntor::{classic_ntor, quantum_safe_ntor};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, BenchmarkGroup};
use std::fs::OpenOptions;
use std::io;
use csv::WriterBuilder;
use std::fmt::Display;
use std::time::{Duration, Instant};
fn csv_writer(file_name: &str, function_name: &str, duration: Duration) -> io::Result<()> {

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
        format!("{:?}", duration).as_str(),
    ])?;
    wtr.flush()?;

    Ok(())
}

fn classic() {
    let start = Instant::now();
    let classic_handshake = classic_ntor::ClassicNtorTcp::new();
    let (client_reply_size, server_reply_size) = classic_handshake.ntor();
    let duration = start.elapsed();
    let _ = csv_writer("classic.csv","ntor_handshake", duration);
}

fn quantum() {
    let start = Instant::now();
    let quantum_handshake = quantum_safe_ntor::QuantumNtorTcp::new();
    let (client_reply_size, server_reply_size) = quantum_handshake.ntor();
    let duration = start.elapsed();
    let _ = csv_writer("quantum.csv","ntor_handshake", duration);
}

fn bench_ntor(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntor_roup");
    group.measurement_time(Duration::from_secs(300));
    group.sample_size(2000); // Set sample size to 1000

    group.bench_function("classic_ntor", |b| b.iter(|| classic()));
    group.bench_function("quantum.ntor", |b| b.iter(|| quantum()));

    group.finish()
}

criterion_group!(benches, bench_ntor);
criterion_main!(benches);





