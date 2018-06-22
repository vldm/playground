# [Draft] Research for seperating message 

This playground represent code for comparative analysis for message representation.

Module `message` in `/src/message/` folder contain contains almost the latest messages design with seperate structure for messages.

Module `old_message` in `/src/old_message/` folder contain old design with `macros`.

Currently only `benchmarks`, and `printing` demos available.

Running benches:

```
cargo run --bin criterion --release
``` 

Print binnary representation:

```
cargo run --bin main --release
``` 