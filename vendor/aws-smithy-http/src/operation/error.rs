/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Errors for operations

use aws_smithy_types::date_time::DateTimeFormatError;
use http::uri::InvalidUri;
use std::borrow::Cow;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
enum SerializationErrorKind {
    CannotSerializeUnknownVariant { union: &'static str },
    DateTimeFormatError { cause: DateTimeFormatError },
}

#[derive(Debug)]
pub struct SerializationError {
    kind: SerializationErrorKind,
}

impl SerializationError {
    pub fn unknown_variant(union: &'static str) -> Self {
        Self {
            kind: SerializationErrorKind::CannotSerializeUnknownVariant { union },
        }
    }
}

impl Display for SerializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SerializationErrorKind::CannotSerializeUnknownVariant { union } => write!(
                f,
                "Cannot serialize `{union}::Unknown`. Unknown union variants cannot be serialized. \
                This can occur when round-tripping a response from the server that was not \
                recognized by the SDK. Consider upgrading to the latest version of the SDK.",
            ),
            SerializationErrorKind::DateTimeFormatError { .. } => {
                write!(f, "failed to serialize timestamp")
            }
        }
    }
}

impl Error for SerializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            SerializationErrorKind::CannotSerializeUnknownVariant { .. } => None,
            SerializationErrorKind::DateTimeFormatError { cause } => Some(cause as _),
        }
    }
}

impl From<DateTimeFormatError> for SerializationError {
    fn from(err: DateTimeFormatError) -> SerializationError {
        Self {
            kind: SerializationErrorKind::DateTimeFormatError { cause: err },
        }
    }
}

#[derive(Debug)]
enum BuildErrorKind {
    /// A field contained an invalid value
    InvalidField {
        field: &'static str,
        details: String,
    },
    /// A field was missing
    MissingField {
        field: &'static str,
        details: &'static str,
    },
    /// The serializer could not serialize the input
    SerializationError(SerializationError),

    /// The serializer did not produce a valid URI
    ///
    /// This typically indicates that a field contained invalid characters.
    InvalidUri {
        uri: String,
        message: Cow<'static, str>,
        source: InvalidUri,
    },

    /// An error occurred request construction
    Other(Box<dyn Error + Send + Sync + 'static>),
}

/// An error occurred attempting to build an `Operation` from an input
///
/// These are almost always due to user error caused by limitations of specific fields due to
/// protocol serialization (e.g. fields that can only be a subset ASCII because they are serialized
/// as the name of an HTTP header)
#[derive(Debug)]
pub struct BuildError {
    kind: BuildErrorKind,
}

impl BuildError {
    pub(crate) fn invalid_uri(uri: String, message: Cow<'static, str>, source: InvalidUri) -> Self {
        Self {
            kind: BuildErrorKind::InvalidUri {
                uri,
                message,
                source,
            },
        }
    }

    /// Construct a build error for a missing field
    pub fn missing_field(field: &'static str, details: &'static str) -> Self {
        Self {
            kind: BuildErrorKind::MissingField { field, details },
        }
    }

    /// Construct a build error for a missing field
    pub fn invalid_field(field: &'static str, details: impl Into<String>) -> Self {
        Self {
            kind: BuildErrorKind::InvalidField {
                field,
                details: details.into(),
            },
        }
    }

    /// Construct a build error from another underlying error
    pub fn other(source: impl Into<Box<dyn Error + Send + Sync + 'static>>) -> Self {
        Self {
            kind: BuildErrorKind::Other(source.into()),
        }
    }
}

impl From<SerializationError> for BuildError {
    fn from(err: SerializationError) -> Self {
        Self {
            kind: BuildErrorKind::SerializationError(err),
        }
    }
}

impl From<DateTimeFormatError> for BuildError {
    fn from(err: DateTimeFormatError) -> Self {
        Self::from(SerializationError::from(err))
    }
}

impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            BuildErrorKind::InvalidField { field, details } => {
                write!(f, "invalid field in input: {field} (details: {details})")
            }
            BuildErrorKind::MissingField { field, details } => {
                write!(f, "{field} was missing: {details}")
            }
            BuildErrorKind::SerializationError(_) => {
                write!(f, "failed to serialize input")
            }
            BuildErrorKind::InvalidUri { uri, message, .. } => {
                write!(f, "generated URI `{uri}` was not a valid URI: {message}")
            }
            BuildErrorKind::Other(_) => {
                write!(f, "error during request construction")
            }
        }
    }
}

impl Error for BuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            BuildErrorKind::SerializationError(source) => Some(source as _),
            BuildErrorKind::Other(source) => Some(source.as_ref()),
            BuildErrorKind::InvalidUri { source, .. } => Some(source as _),
            BuildErrorKind::InvalidField { .. } | BuildErrorKind::MissingField { .. } => None,
        }
    }
}
