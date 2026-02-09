## Instructions

We provide three Cargo macros for testing:

- `cargo tr-sh` — semi-honest protocol (one-sided output)

- `cargo tr-1m` — malicious protocol (one-sided output)

- `cargo tr-2m` — malicious protocol (two-sided output)

The input set sizes for both parties are passed via environment variables. By default, all protocols are evaluated in the worst-case scenario where the two sets have an empty intersection. If larger intersections are allowed, performance will improve accordingly.

On macOS or Linux, you can run:

```bash
N=1000 cargo tr-sh
```
or

```bash
N=2^10 cargo tr-sh
```

to test the semi-honest protocol with set sizes of `1000` or `1024`, respectively.

On Windows, first set the environment variable: `$env:N=1000` or `$env:N=2^10`, and then run:

```bash
cargo tr-sh
```
directly.

If needed, you can check `/.cargo/config.toml` to adjust compiler flags for better optimization. 