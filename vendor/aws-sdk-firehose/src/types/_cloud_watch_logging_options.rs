// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the Amazon CloudWatch logging options for your delivery stream.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchLoggingOptions {
    /// <p>Enables or disables CloudWatch logging.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>The CloudWatch group name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The CloudWatch log stream name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub log_stream_name: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLoggingOptions {
    /// <p>Enables or disables CloudWatch logging.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>The CloudWatch group name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>The CloudWatch log stream name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn log_stream_name(&self) -> ::std::option::Option<&str> {
        self.log_stream_name.as_deref()
    }
}
impl CloudWatchLoggingOptions {
    /// Creates a new builder-style object to manufacture [`CloudWatchLoggingOptions`](crate::types::CloudWatchLoggingOptions).
    pub fn builder() -> crate::types::builders::CloudWatchLoggingOptionsBuilder {
        crate::types::builders::CloudWatchLoggingOptionsBuilder::default()
    }
}

/// A builder for [`CloudWatchLoggingOptions`](crate::types::CloudWatchLoggingOptions).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct CloudWatchLoggingOptionsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) log_stream_name: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLoggingOptionsBuilder {
    /// <p>Enables or disables CloudWatch logging.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables CloudWatch logging.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Enables or disables CloudWatch logging.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The CloudWatch group name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CloudWatch group name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The CloudWatch group name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>The CloudWatch log stream name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn log_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CloudWatch log stream name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn set_log_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_stream_name = input;
        self
    }
    /// <p>The CloudWatch log stream name for logging. This value is required if CloudWatch logging is enabled.</p>
    pub fn get_log_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_stream_name
    }
    /// Consumes the builder and constructs a [`CloudWatchLoggingOptions`](crate::types::CloudWatchLoggingOptions).
    pub fn build(self) -> crate::types::CloudWatchLoggingOptions {
        crate::types::CloudWatchLoggingOptions {
            enabled: self.enabled,
            log_group_name: self.log_group_name,
            log_stream_name: self.log_stream_name,
        }
    }
}