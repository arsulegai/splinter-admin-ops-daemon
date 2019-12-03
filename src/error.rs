// Copyright 2019 Cargill Incorporated
// Copyright 2019 Walmart Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::error::Error;
use std::fmt;

use sawtooth_sdk::signing::Error as KeyGenError;

use crate::rest_api::RestApiServerError;

#[derive(Debug)]
pub enum AdminOpDaemonError {
    LoggingInitializationError(flexi_logger::FlexiLoggerError),
    ConfigurationError(Box<ConfigurationError>),
    RestApiError(RestApiServerError),
    KeyGenError(KeyGenError),
    GetNodeError(GetNodeError),
}

impl Error for AdminOpDaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AdminOpDaemonError::LoggingInitializationError(err) => Some(err),
            AdminOpDaemonError::ConfigurationError(err) => Some(err),
            AdminOpDaemonError::RestApiError(err) => Some(err),
            AdminOpDaemonError::KeyGenError(err) => Some(err),
            AdminOpDaemonError::GetNodeError(err) => Some(err),
        }
    }
}

impl fmt::Display for AdminOpDaemonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AdminOpDaemonError::LoggingInitializationError(e) => {
                write!(f, "Logging initialization error: {}", e)
            }
            AdminOpDaemonError::ConfigurationError(e) => write!(f, "Coniguration error: {}", e),
            AdminOpDaemonError::RestApiError(e) => write!(f, "Rest API error: {}", e),
            AdminOpDaemonError::KeyGenError(e) => write!(
                f,
                "an error occurred while generating a new key pair: {}",
                e
            ),
            AdminOpDaemonError::GetNodeError(e) => write!(
                f,
                "an error occurred while getting splinterd node information: {}",
                e
            ),
        }
    }
}

impl From<flexi_logger::FlexiLoggerError> for AdminOpDaemonError {
    fn from(err: flexi_logger::FlexiLoggerError) -> AdminOpDaemonError {
        AdminOpDaemonError::LoggingInitializationError(err)
    }
}

impl From<RestApiServerError> for AdminOpDaemonError {
    fn from(err: RestApiServerError) -> AdminOpDaemonError {
        AdminOpDaemonError::RestApiError(err)
    }
}

impl From<KeyGenError> for AdminOpDaemonError {
    fn from(err: KeyGenError) -> AdminOpDaemonError {
        AdminOpDaemonError::KeyGenError(err)
    }
}

#[derive(Debug, PartialEq)]
pub enum ConfigurationError {
    MissingValue(String),
}

impl Error for ConfigurationError {}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigurationError::MissingValue(config_field_name) => {
                write!(f, "Missing configuration for {}", config_field_name)
            }
        }
    }
}

impl From<ConfigurationError> for AdminOpDaemonError {
    fn from(err: ConfigurationError) -> Self {
        AdminOpDaemonError::ConfigurationError(Box::new(err))
    }
}

#[derive(Debug, PartialEq)]
pub struct GetNodeError(pub String);

impl Error for GetNodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for GetNodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<GetNodeError> for AdminOpDaemonError {
    fn from(err: GetNodeError) -> Self {
        AdminOpDaemonError::GetNodeError(err)
    }
}
