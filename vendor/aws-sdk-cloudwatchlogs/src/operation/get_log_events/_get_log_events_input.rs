// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLogEventsInput {
    /// <p>The name of the log group.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>Specify either the name or ARN of the log group to view events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub log_group_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the log stream.</p>
    pub log_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to this time or later than this time are included. Events with a timestamp earlier than this time are not included.</p>
    pub start_time: ::std::option::Option<i64>,
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to or later than this time are not included.</p>
    pub end_time: ::std::option::Option<i64>,
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of log events returned. If you don't specify a limit, the default is as many log events as can fit in a response size of 1 MB (up to 10,000 log events).</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>If the value is true, the earliest log events are returned first. If the value is false, the latest log events are returned first. The default value is false.</p>
    /// <p>If you are using a previous <code>nextForwardToken</code> value as the <code>nextToken</code> in this operation, you must specify <code>true</code> for <code>startFromHead</code>.</p>
    pub start_from_head: ::std::option::Option<bool>,
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub unmask: ::std::option::Option<bool>,
}
impl GetLogEventsInput {
    /// <p>The name of the log group.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>Specify either the name or ARN of the log group to view events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn log_group_identifier(&self) -> ::std::option::Option<&str> {
        self.log_group_identifier.as_deref()
    }
    /// <p>The name of the log stream.</p>
    pub fn log_stream_name(&self) -> ::std::option::Option<&str> {
        self.log_stream_name.as_deref()
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to this time or later than this time are included. Events with a timestamp earlier than this time are not included.</p>
    pub fn start_time(&self) -> ::std::option::Option<i64> {
        self.start_time
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to or later than this time are not included.</p>
    pub fn end_time(&self) -> ::std::option::Option<i64> {
        self.end_time
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of log events returned. If you don't specify a limit, the default is as many log events as can fit in a response size of 1 MB (up to 10,000 log events).</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>If the value is true, the earliest log events are returned first. If the value is false, the latest log events are returned first. The default value is false.</p>
    /// <p>If you are using a previous <code>nextForwardToken</code> value as the <code>nextToken</code> in this operation, you must specify <code>true</code> for <code>startFromHead</code>.</p>
    pub fn start_from_head(&self) -> ::std::option::Option<bool> {
        self.start_from_head
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn unmask(&self) -> ::std::option::Option<bool> {
        self.unmask
    }
}
impl GetLogEventsInput {
    /// Creates a new builder-style object to manufacture [`GetLogEventsInput`](crate::operation::get_log_events::GetLogEventsInput).
    pub fn builder() -> crate::operation::get_log_events::builders::GetLogEventsInputBuilder {
        crate::operation::get_log_events::builders::GetLogEventsInputBuilder::default()
    }
}

/// A builder for [`GetLogEventsInput`](crate::operation::get_log_events::GetLogEventsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetLogEventsInputBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) log_group_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) log_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<i64>,
    pub(crate) end_time: ::std::option::Option<i64>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) start_from_head: ::std::option::Option<bool>,
    pub(crate) unmask: ::std::option::Option<bool>,
}
impl GetLogEventsInputBuilder {
    /// <p>The name of the log group.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log group.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The name of the log group.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>Specify either the name or ARN of the log group to view events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn log_group_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify either the name or ARN of the log group to view events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn set_log_group_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_identifier = input;
        self
    }
    /// <p>Specify either the name or ARN of the log group to view events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn get_log_group_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_identifier
    }
    /// <p>The name of the log stream.</p>
    /// This field is required.
    pub fn log_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log stream.</p>
    pub fn set_log_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_stream_name = input;
        self
    }
    /// <p>The name of the log stream.</p>
    pub fn get_log_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_stream_name
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to this time or later than this time are included. Events with a timestamp earlier than this time are not included.</p>
    pub fn start_time(mut self, input: i64) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to this time or later than this time are included. Events with a timestamp earlier than this time are not included.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to this time or later than this time are included. Events with a timestamp earlier than this time are not included.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<i64> {
        &self.start_time
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to or later than this time are not included.</p>
    pub fn end_time(mut self, input: i64) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to or later than this time are not included.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp equal to or later than this time are not included.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<i64> {
        &self.end_time
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of log events returned. If you don't specify a limit, the default is as many log events as can fit in a response size of 1 MB (up to 10,000 log events).</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of log events returned. If you don't specify a limit, the default is as many log events as can fit in a response size of 1 MB (up to 10,000 log events).</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of log events returned. If you don't specify a limit, the default is as many log events as can fit in a response size of 1 MB (up to 10,000 log events).</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>If the value is true, the earliest log events are returned first. If the value is false, the latest log events are returned first. The default value is false.</p>
    /// <p>If you are using a previous <code>nextForwardToken</code> value as the <code>nextToken</code> in this operation, you must specify <code>true</code> for <code>startFromHead</code>.</p>
    pub fn start_from_head(mut self, input: bool) -> Self {
        self.start_from_head = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the value is true, the earliest log events are returned first. If the value is false, the latest log events are returned first. The default value is false.</p>
    /// <p>If you are using a previous <code>nextForwardToken</code> value as the <code>nextToken</code> in this operation, you must specify <code>true</code> for <code>startFromHead</code>.</p>
    pub fn set_start_from_head(mut self, input: ::std::option::Option<bool>) -> Self {
        self.start_from_head = input;
        self
    }
    /// <p>If the value is true, the earliest log events are returned first. If the value is false, the latest log events are returned first. The default value is false.</p>
    /// <p>If you are using a previous <code>nextForwardToken</code> value as the <code>nextToken</code> in this operation, you must specify <code>true</code> for <code>startFromHead</code>.</p>
    pub fn get_start_from_head(&self) -> &::std::option::Option<bool> {
        &self.start_from_head
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn unmask(mut self, input: bool) -> Self {
        self.unmask = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn set_unmask(mut self, input: ::std::option::Option<bool>) -> Self {
        self.unmask = input;
        self
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn get_unmask(&self) -> &::std::option::Option<bool> {
        &self.unmask
    }
    /// Consumes the builder and constructs a [`GetLogEventsInput`](crate::operation::get_log_events::GetLogEventsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_log_events::GetLogEventsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_log_events::GetLogEventsInput {
            log_group_name: self.log_group_name,
            log_group_identifier: self.log_group_identifier,
            log_stream_name: self.log_stream_name,
            start_time: self.start_time,
            end_time: self.end_time,
            next_token: self.next_token,
            limit: self.limit,
            start_from_head: self.start_from_head,
            unmask: self.unmask,
        })
    }
}