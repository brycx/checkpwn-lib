// MIT License

// Copyright (c) 2020-2021 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! # Usage:
//! ```rust
//! use checkpwn_lib::{Password, check_password, check_account, CheckpwnError};
//!
//! let password = Password::new("qwerty")?;
//! check_password(&password);
//!
//!
//! check_account("your_account", "your_api_key");
//!
//! # Ok::<(), CheckpwnError>(())
//! ```
#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_qualifications,
    overflowing_literals
)]
#![doc(html_root_url = "https://docs.rs/checkpwn_lib/0.2.0")]

mod api;
mod errors;

pub use errors::CheckpwnError;
use std::{thread, time};

/// The checkpwn UserAgent sent to HIBP.
pub const CHECKPWN_USER_AGENT: &str = "checkpwn - cargo utility tool for hibp";

/// Check account, on both account and paste databases, using a given API key.
/// Before sending a request, the thread sleeps for 1600 millis. HIBP limits at 1500.
/// Returns Ok(bool), `bool` indicating whether the account is breached or not.
/// Err() is returned if an error occurred during the check.
pub fn check_account(account: &str, api_key: &str) -> Result<bool, CheckpwnError> {
    if account.is_empty() || api_key.is_empty() {
        return Err(CheckpwnError::EmptyInput);
    }

    // HIBP limits requests to one per 1500 milliseconds. We're allowing for 1600 below as a buffer.
    thread::sleep(time::Duration::from_millis(1600));

    let acc_db_api_route = api::arg_to_api_route(&api::CheckableChoices::Acc, account);
    let paste_db_api_route = api::arg_to_api_route(&api::CheckableChoices::Paste, account);

    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .timeout_connect(time::Duration::from_secs(10))
        .build();

    let acc_stat = agent
        .get(&acc_db_api_route)
        .set("User-Agent", CHECKPWN_USER_AGENT)
        .set("hibp-api-key", api_key)
        .call();

    let paste_stat = agent
        .get(&paste_db_api_route)
        .set("User-Agent", CHECKPWN_USER_AGENT)
        .set("hibp-api-key", api_key)
        .call();

    api::evaluate_acc_breach_statuscodes(
        api::response_to_status_codes(&acc_stat)?,
        api::response_to_status_codes(&paste_stat)?,
    )
}

/// `Password` is a wrapper type for a password that is checked at HIBP.
/// It contains an opaque `Debug` impl, to avoid the SHA1 hash of the password to leak.
pub struct Password {
    hash: String,
}

impl Password {
    /// Hash and make a new `Password`. Returns `Err` if `password` is empty.
    pub fn new(password: &str) -> Result<Self, CheckpwnError> {
        if password.is_empty() {
            return Err(CheckpwnError::EmptyInput);
        }

        Ok(Self {
            hash: api::hash_password(password),
        })
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password {{ hash: ***OMITTED*** }}")
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.hash.zeroize()
    }
}

/// Check password.
/// Returns Ok(bool), `bool` indicating whether the password is breached or not.
/// Err() is returned if an error occurred during the check.
pub fn check_password(password: &Password) -> Result<bool, CheckpwnError> {
    let pass_db_api_route = api::arg_to_api_route(&api::CheckableChoices::Pass, &password.hash);

    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .timeout_connect(time::Duration::from_secs(10))
        .build();

    let pass_stat = agent
        .get(&pass_db_api_route)
        .set("User-Agent", CHECKPWN_USER_AGENT)
        .set("Add-Padding", "true")
        .call();

    let request_status = api::response_to_status_codes(&pass_stat)?;
    // An error here that would abort the check will be returned already from the above
    // so unwrap() here should be fine
    let pass_body: String = pass_stat.unwrap().into_string().unwrap();

    if api::search_in_range(&pass_body, &password.hash) {
        if request_status == 200 {
            Ok(true)
        } else if request_status == 404 {
            Ok(false)
        } else {
            Err(CheckpwnError::StatusCode)
        }
    } else {
        Ok(false)
    }
}
#[test]
fn test_empty_input_errors() {
    assert!(check_account("", "Test").is_err());
    assert!(check_account("Test", "").is_err());
    assert!(Password::new("").is_err());
}

#[cfg(test)]
#[cfg(feature = "ci_test")]
fn get_env_api_key_from_ci() -> String {
    // If in CI, the key is in env.
    // TODO: Local tests are not handled and simply fail.
    std::env::var("API_KEY").unwrap()
}

#[cfg(feature = "ci_test")]
#[test]
fn test_check_account() {
    let api_key = get_env_api_key_from_ci();

    assert_eq!(check_account("test@example.com", &api_key).unwrap(), true);
    assert_eq!(
        check_account("fsrEos7s@wZ3zdGxr.com", &api_key).unwrap(),
        false
    );
}

#[test]
fn test_check_password() {
    let breached_password = Password::new("qwerty").unwrap();
    let non_breached_password = Password::new("dHRUKbDaKgIobOtX").unwrap();

    assert_eq!(check_password(&breached_password).unwrap(), true);
    assert_eq!(check_password(&non_breached_password).unwrap(), false);
}
