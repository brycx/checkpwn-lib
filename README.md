## checkpwn-lib ![Build Status](https://api.travis-ci.com/brycx/checkpwn-lib.svg?branch=main) [![codecov](https://codecov.io/gh/brycx/checkpwn-lib/branch/main/graph/badge.svg)](https://codecov.io/gh/brycx/checkpwn-lib) [![Documentation](https://docs.rs/checkpwn-lib/badge.svg)](https://docs.rs/checkpwn-lib/) [![Crates.io](https://img.shields.io/crates/v/checkpwn-lib.svg)](https://crates.io/crates/checkpwn-lib) [![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
Library to interact with the [Have I Been Pwned](https://haveibeenpwned.com/) API.

See also the [checkpwn](https://github.com/brycx/checkpwn) CLI utility.

### Usage
```rust
use checkpwn_lib::{Password, check_password, check_account, CheckpwnError};

let password = Password::new("qwerty")?;
check_password(&password);


check_account("your_account", "your_api_key");
```

### Changelog

See [here](https://github.com/brycx/checkpwn-lib/releases).

### License
checkpwn is licensed under the MIT license. See the `LICENSE` file for more information.
