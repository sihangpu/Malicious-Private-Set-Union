use criterion::{criterion_group, criterion_main, Criterion};
use m2psu::onesided::{semi_honest_psu1, sender_malicious_psu1};
use m2psu::twosided::{generate_input, malicious_psu2};

fn setup_data() -> Vec<u8> {
    // e.g., generate a buffer or test dataset once
    (0..1000).map(|i| i as u8).collect()
}

// 2. A benchmarking function that tells Criterion how to run your code
fn bench_your_function(c: &mut Criterion) {
    // Create or select a benchmark group
    let mut group = c.benchmark_group("semi_honest_one_sided_psu");

    // Configure the number of times each sample runs
    // This makes Criterion run your function 10 times per sample.
    group.sample_size(10);

    // Register your function
    group.bench_function("your_function_label", |b| {
        // b.iter(|| semi_honest_psu1());
    });

    // Finish the group to output results
    group.finish();
}

// 3. Boilerplate to wire everything up
criterion_group!(benches, bench_your_function);
criterion_main!(benches);
