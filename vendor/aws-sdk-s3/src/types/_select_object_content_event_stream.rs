// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The container for selecting objects from a content event stream.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum SelectObjectContentEventStream {
    /// <p>The Continuation Event.</p>
    Cont(crate::types::ContinuationEvent),
    /// <p>The End Event.</p>
    End(crate::types::EndEvent),
    /// <p>The Progress Event.</p>
    Progress(crate::types::ProgressEvent),
    /// <p>The Records Event.</p>
    Records(crate::types::RecordsEvent),
    /// <p>The Stats Event.</p>
    Stats(crate::types::StatsEvent),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl SelectObjectContentEventStream {
    /// Tries to convert the enum instance into [`Cont`](crate::types::SelectObjectContentEventStream::Cont), extracting the inner [`ContinuationEvent`](crate::types::ContinuationEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cont(&self) -> ::std::result::Result<&crate::types::ContinuationEvent, &Self> {
        if let SelectObjectContentEventStream::Cont(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Cont`](crate::types::SelectObjectContentEventStream::Cont).
    pub fn is_cont(&self) -> bool {
        self.as_cont().is_ok()
    }
    /// Tries to convert the enum instance into [`End`](crate::types::SelectObjectContentEventStream::End), extracting the inner [`EndEvent`](crate::types::EndEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_end(&self) -> ::std::result::Result<&crate::types::EndEvent, &Self> {
        if let SelectObjectContentEventStream::End(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`End`](crate::types::SelectObjectContentEventStream::End).
    pub fn is_end(&self) -> bool {
        self.as_end().is_ok()
    }
    /// Tries to convert the enum instance into [`Progress`](crate::types::SelectObjectContentEventStream::Progress), extracting the inner [`ProgressEvent`](crate::types::ProgressEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_progress(&self) -> ::std::result::Result<&crate::types::ProgressEvent, &Self> {
        if let SelectObjectContentEventStream::Progress(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Progress`](crate::types::SelectObjectContentEventStream::Progress).
    pub fn is_progress(&self) -> bool {
        self.as_progress().is_ok()
    }
    /// Tries to convert the enum instance into [`Records`](crate::types::SelectObjectContentEventStream::Records), extracting the inner [`RecordsEvent`](crate::types::RecordsEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_records(&self) -> ::std::result::Result<&crate::types::RecordsEvent, &Self> {
        if let SelectObjectContentEventStream::Records(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Records`](crate::types::SelectObjectContentEventStream::Records).
    pub fn is_records(&self) -> bool {
        self.as_records().is_ok()
    }
    /// Tries to convert the enum instance into [`Stats`](crate::types::SelectObjectContentEventStream::Stats), extracting the inner [`StatsEvent`](crate::types::StatsEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_stats(&self) -> ::std::result::Result<&crate::types::StatsEvent, &Self> {
        if let SelectObjectContentEventStream::Stats(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Stats`](crate::types::SelectObjectContentEventStream::Stats).
    pub fn is_stats(&self) -> bool {
        self.as_stats().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}