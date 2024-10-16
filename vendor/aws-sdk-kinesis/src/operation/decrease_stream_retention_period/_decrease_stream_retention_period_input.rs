// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input for <code>DecreaseStreamRetentionPeriod</code>.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DecreaseStreamRetentionPeriodInput {
    /// <p>The name of the stream to modify.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The new retention period of the stream, in hours. Must be less than the current retention period.</p>
    pub retention_period_hours: ::std::option::Option<i32>,
    /// <p>The ARN of the stream.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
}
impl DecreaseStreamRetentionPeriodInput {
    /// <p>The name of the stream to modify.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The new retention period of the stream, in hours. Must be less than the current retention period.</p>
    pub fn retention_period_hours(&self) -> ::std::option::Option<i32> {
        self.retention_period_hours
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
}
impl DecreaseStreamRetentionPeriodInput {
    /// Creates a new builder-style object to manufacture [`DecreaseStreamRetentionPeriodInput`](crate::operation::decrease_stream_retention_period::DecreaseStreamRetentionPeriodInput).
    pub fn builder() -> crate::operation::decrease_stream_retention_period::builders::DecreaseStreamRetentionPeriodInputBuilder {
        crate::operation::decrease_stream_retention_period::builders::DecreaseStreamRetentionPeriodInputBuilder::default()
    }
}

/// A builder for [`DecreaseStreamRetentionPeriodInput`](crate::operation::decrease_stream_retention_period::DecreaseStreamRetentionPeriodInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DecreaseStreamRetentionPeriodInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) retention_period_hours: ::std::option::Option<i32>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
}
impl DecreaseStreamRetentionPeriodInputBuilder {
    /// <p>The name of the stream to modify.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream to modify.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream to modify.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The new retention period of the stream, in hours. Must be less than the current retention period.</p>
    /// This field is required.
    pub fn retention_period_hours(mut self, input: i32) -> Self {
        self.retention_period_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new retention period of the stream, in hours. Must be less than the current retention period.</p>
    pub fn set_retention_period_hours(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retention_period_hours = input;
        self
    }
    /// <p>The new retention period of the stream, in hours. Must be less than the current retention period.</p>
    pub fn get_retention_period_hours(&self) -> &::std::option::Option<i32> {
        &self.retention_period_hours
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// Consumes the builder and constructs a [`DecreaseStreamRetentionPeriodInput`](crate::operation::decrease_stream_retention_period::DecreaseStreamRetentionPeriodInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::decrease_stream_retention_period::DecreaseStreamRetentionPeriodInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::decrease_stream_retention_period::DecreaseStreamRetentionPeriodInput {
            stream_name: self.stream_name,
            retention_period_hours: self.retention_period_hours,
            stream_arn: self.stream_arn,
        })
    }
}