// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the status of an export task.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportTaskExecutionInfo {
    /// <p>The creation time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub creation_time: ::std::option::Option<i64>,
    /// <p>The completion time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub completion_time: ::std::option::Option<i64>,
}
impl ExportTaskExecutionInfo {
    /// <p>The creation time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn creation_time(&self) -> ::std::option::Option<i64> {
        self.creation_time
    }
    /// <p>The completion time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn completion_time(&self) -> ::std::option::Option<i64> {
        self.completion_time
    }
}
impl ExportTaskExecutionInfo {
    /// Creates a new builder-style object to manufacture [`ExportTaskExecutionInfo`](crate::types::ExportTaskExecutionInfo).
    pub fn builder() -> crate::types::builders::ExportTaskExecutionInfoBuilder {
        crate::types::builders::ExportTaskExecutionInfoBuilder::default()
    }
}

/// A builder for [`ExportTaskExecutionInfo`](crate::types::ExportTaskExecutionInfo).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ExportTaskExecutionInfoBuilder {
    pub(crate) creation_time: ::std::option::Option<i64>,
    pub(crate) completion_time: ::std::option::Option<i64>,
}
impl ExportTaskExecutionInfoBuilder {
    /// <p>The creation time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn creation_time(mut self, input: i64) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The creation time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<i64> {
        &self.creation_time
    }
    /// <p>The completion time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn completion_time(mut self, input: i64) -> Self {
        self.completion_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The completion time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn set_completion_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.completion_time = input;
        self
    }
    /// <p>The completion time of the export task, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>.</p>
    pub fn get_completion_time(&self) -> &::std::option::Option<i64> {
        &self.completion_time
    }
    /// Consumes the builder and constructs a [`ExportTaskExecutionInfo`](crate::types::ExportTaskExecutionInfo).
    pub fn build(self) -> crate::types::ExportTaskExecutionInfo {
        crate::types::ExportTaskExecutionInfo {
            creation_time: self.creation_time,
            completion_time: self.completion_time,
        }
    }
}