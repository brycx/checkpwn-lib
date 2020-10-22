// MIT License

// Copyright (c) 2020 brycx

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

/// Errors related to checking passwords and accounts.
#[derive(Clone, Copy, PartialEq)]
pub enum CheckpwnError {
    ///
    StatusCode,
    ///
    Network,
    ///
    Decoding,
    ///
    BadResponse,
    ///
    InvalidApiKey,
    ///
    MissingApiKey,
    ///
    EmptyInput,
}

impl AsRef<str> for CheckpwnError {
    fn as_ref(&self) -> &str {
        match *self {
            CheckpwnError::StatusCode => "Unrecognized status code received",
            CheckpwnError::Network => "Failed to send request to HIBP",
            CheckpwnError::Decoding => "Failed to decode response from HIBP",
            CheckpwnError::BadResponse => {
                "Received a bad response from HIBP - make sure the account is valid"
            }
            CheckpwnError::InvalidApiKey => "HIBP deemed the current API key invalid",
            CheckpwnError::MissingApiKey => "The API key is missing",
            CheckpwnError::EmptyInput => "Empty input that should NOT be empty",
        }
    }
}

impl std::fmt::Display for CheckpwnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl std::fmt::Debug for CheckpwnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl std::error::Error for CheckpwnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
