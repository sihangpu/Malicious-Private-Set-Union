#Instructions

There are three macros for testing: `cargo tr-sh`, `cargo tr-1m`, and `cargo tr-2m` for semi-honest protocol (one-sided output), malicious protocol (one-sided output), and malicious protocol (two-sided output). The input size for both parties are transferred through environment variables. The default setting for protocols are in the worst case that the intersection is empty for two sets, which means the performance would be better if allow larger intersection.

On MacOS/Linux, run `N=1000 cargo tr-sh` or `N=2^10 cargo tr-sh` for semi-honest protcol with set size `1000` or `1024`.

On Windows, set env-variable first via `$env:N=1000`, then run `cargo tr-sh` directly.

If necessary, you can check `/.cargo/config.toml` to adjust specific compiler flags for better optimization.
