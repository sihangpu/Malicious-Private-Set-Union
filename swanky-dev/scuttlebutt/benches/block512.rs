#![allow(clippy::all)]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand::Rng;
use scuttlebutt::{AesRng, Block512};

fn bench_rand(c: &mut Criterion) {
    c.bench_function("Block512::rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| {
            let block = rng.r#gen::<Block512>();
            black_box(block)
        });
    });
}

criterion_group! {
    name = block512;
    config = Criterion::default();
    targets = bench_rand
}
criterion_main!(block512);
