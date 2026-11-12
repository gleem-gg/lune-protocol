# lune-protocol

The [Lune](https://lune.gleem.gg/) bonding protocol as a Rust crate: what a
sender and an ingest have to agree on byte for byte.

- `packet`: framing and every packet type, encode and decode
- `cookie`: the stateless HELLO → COOKIE check
- `ticket`: verifying (and, for tests and operators, minting) tickets
- `srt`: the two bits of an SRT header a scheduler looks at
- `dedup`, `reorder`: dropping duplicate copies, and putting packets back in order
- the limits and timers, and serial-number arithmetic for `link_seq`

The specification's test vectors are this crate's unit tests:

```bash
cargo test
```

[`lune-server`](https://github.com/gleem-gg/lune) is a minimal ingest for the
same specification.

A few items go beyond the specification because Gleem's ingest uses them
(`play` tickets, `Forward::Turn`, `srt_passphrase`); their documentation says
so. An ingest or sender that only follows the specification can ignore them.

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
