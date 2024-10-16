// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::filter_log_events::_filter_log_events_output::FilterLogEventsOutputBuilder;

pub use crate::operation::filter_log_events::_filter_log_events_input::FilterLogEventsInputBuilder;

impl FilterLogEventsInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::filter_log_events::FilterLogEventsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::filter_log_events::FilterLogEventsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.filter_log_events();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `FilterLogEvents`.
///
/// <p>Lists log events from the specified log group. You can list all the log events or filter the results using a filter pattern, a time range, and the name of the log stream.</p>
/// <p>You must have the <code>logs:FilterLogEvents</code> permission to perform this operation.</p>
/// <p>You can specify the log group to search by using either <code>logGroupIdentifier</code> or <code>logGroupName</code>. You must include one of these two parameters, but you can't include both. </p>
/// <p>By default, this operation returns as many log events as can fit in 1 MB (up to 10,000 log events) or all the events found within the specified time range. If the results include a token, that means there are more log events available. You can get additional results by specifying the token in a subsequent call. This operation can return empty results while there are more log events available through the token.</p>
/// <p>The returned log events are sorted by event timestamp, the timestamp when the event was ingested by CloudWatch Logs, and the ID of the <code>PutLogEvents</code> request.</p>
/// <p>If you are using CloudWatch cross-account observability, you can use this operation in a monitoring account and view data from the linked source accounts. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Unified-Cross-Account.html">CloudWatch cross-account observability</a>.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct FilterLogEventsFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::filter_log_events::builders::FilterLogEventsInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::filter_log_events::FilterLogEventsOutput,
        crate::operation::filter_log_events::FilterLogEventsError,
    > for FilterLogEventsFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::filter_log_events::FilterLogEventsOutput,
            crate::operation::filter_log_events::FilterLogEventsError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl FilterLogEventsFluentBuilder {
    /// Creates a new `FilterLogEvents`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the FilterLogEvents as a reference.
    pub fn as_input(&self) -> &crate::operation::filter_log_events::builders::FilterLogEventsInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::filter_log_events::FilterLogEventsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::filter_log_events::FilterLogEventsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::filter_log_events::FilterLogEvents::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::filter_log_events::FilterLogEvents::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::filter_log_events::FilterLogEventsOutput,
        crate::operation::filter_log_events::FilterLogEventsError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl Into<crate::config::Builder>) -> Self {
        self.set_config_override(Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// Create a paginator for this request
    ///
    /// Paginators are used by calling [`send().await`](crate::operation::filter_log_events::paginator::FilterLogEventsPaginator::send) which returns a [`PaginationStream`](aws_smithy_async::future::pagination_stream::PaginationStream).
    pub fn into_paginator(self) -> crate::operation::filter_log_events::paginator::FilterLogEventsPaginator {
        crate::operation::filter_log_events::paginator::FilterLogEventsPaginator::new(self.handle, self.inner)
    }
    /// <p>The name of the log group to search.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.log_group_name(input.into());
        self
    }
    /// <p>The name of the log group to search.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_log_group_name(input);
        self
    }
    /// <p>The name of the log group to search.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_log_group_name()
    }
    /// <p>Specify either the name or ARN of the log group to view log events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn log_group_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.log_group_identifier(input.into());
        self
    }
    /// <p>Specify either the name or ARN of the log group to view log events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn set_log_group_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_log_group_identifier(input);
        self
    }
    /// <p>Specify either the name or ARN of the log group to view log events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>
    /// <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>
    /// </note>
    pub fn get_log_group_identifier(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_log_group_identifier()
    }
    /// Appends an item to `logStreamNames`.
    ///
    /// To override the contents of this collection use [`set_log_stream_names`](Self::set_log_stream_names).
    ///
    /// <p>Filters the results to only logs from the log streams in this list.</p>
    /// <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p>
    pub fn log_stream_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.log_stream_names(input.into());
        self
    }
    /// <p>Filters the results to only logs from the log streams in this list.</p>
    /// <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p>
    pub fn set_log_stream_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inner = self.inner.set_log_stream_names(input);
        self
    }
    /// <p>Filters the results to only logs from the log streams in this list.</p>
    /// <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p>
    pub fn get_log_stream_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        self.inner.get_log_stream_names()
    }
    /// <p>Filters the results to include only events from log streams that have names starting with this prefix.</p>
    /// <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, but the value for <code>logStreamNamePrefix</code> does not match any log stream names specified in <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p>
    pub fn log_stream_name_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.log_stream_name_prefix(input.into());
        self
    }
    /// <p>Filters the results to include only events from log streams that have names starting with this prefix.</p>
    /// <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, but the value for <code>logStreamNamePrefix</code> does not match any log stream names specified in <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p>
    pub fn set_log_stream_name_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_log_stream_name_prefix(input);
        self
    }
    /// <p>Filters the results to include only events from log streams that have names starting with this prefix.</p>
    /// <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, but the value for <code>logStreamNamePrefix</code> does not match any log stream names specified in <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p>
    pub fn get_log_stream_name_prefix(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_log_stream_name_prefix()
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp before this time are not returned.</p>
    pub fn start_time(mut self, input: i64) -> Self {
        self.inner = self.inner.start_time(input);
        self
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp before this time are not returned.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.inner = self.inner.set_start_time(input);
        self
    }
    /// <p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp before this time are not returned.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<i64> {
        self.inner.get_start_time()
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp later than this time are not returned.</p>
    pub fn end_time(mut self, input: i64) -> Self {
        self.inner = self.inner.end_time(input);
        self
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp later than this time are not returned.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.inner = self.inner.set_end_time(input);
        self
    }
    /// <p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp later than this time are not returned.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<i64> {
        self.inner.get_end_time()
    }
    /// <p>The filter pattern to use. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    /// <p>If not provided, all the events are matched.</p>
    pub fn filter_pattern(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.filter_pattern(input.into());
        self
    }
    /// <p>The filter pattern to use. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    /// <p>If not provided, all the events are matched.</p>
    pub fn set_filter_pattern(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_filter_pattern(input);
        self
    }
    /// <p>The filter pattern to use. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    /// <p>If not provided, all the events are matched.</p>
    pub fn get_filter_pattern(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_filter_pattern()
    }
    /// <p>The token for the next set of events to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.next_token(input.into());
        self
    }
    /// <p>The token for the next set of events to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_next_token(input);
        self
    }
    /// <p>The token for the next set of events to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_next_token()
    }
    /// <p>The maximum number of events to return. The default is 10,000 events.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.inner = self.inner.limit(input);
        self
    }
    /// <p>The maximum number of events to return. The default is 10,000 events.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_limit(input);
        self
    }
    /// <p>The maximum number of events to return. The default is 10,000 events.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        self.inner.get_limit()
    }
    /// <p>If the value is true, the operation attempts to provide responses that contain events from multiple log streams within the log group, interleaved in a single response. If the value is false, all the matched log events in the first log stream are searched first, then those in the next log stream, and so on.</p>
    /// <p> <b>Important</b> As of June 17, 2019, this parameter is ignored and the value is assumed to be true. The response from this operation always interleaves events from multiple log streams within a log group.</p>
    #[deprecated(
        note = "Starting on June 17, 2019, this parameter will be ignored and the value will be assumed to be true. The response from this operation will always interleave events from multiple log streams within a log group."
    )]
    pub fn interleaved(mut self, input: bool) -> Self {
        self.inner = self.inner.interleaved(input);
        self
    }
    /// <p>If the value is true, the operation attempts to provide responses that contain events from multiple log streams within the log group, interleaved in a single response. If the value is false, all the matched log events in the first log stream are searched first, then those in the next log stream, and so on.</p>
    /// <p> <b>Important</b> As of June 17, 2019, this parameter is ignored and the value is assumed to be true. The response from this operation always interleaves events from multiple log streams within a log group.</p>
    #[deprecated(
        note = "Starting on June 17, 2019, this parameter will be ignored and the value will be assumed to be true. The response from this operation will always interleave events from multiple log streams within a log group."
    )]
    pub fn set_interleaved(mut self, input: ::std::option::Option<bool>) -> Self {
        self.inner = self.inner.set_interleaved(input);
        self
    }
    /// <p>If the value is true, the operation attempts to provide responses that contain events from multiple log streams within the log group, interleaved in a single response. If the value is false, all the matched log events in the first log stream are searched first, then those in the next log stream, and so on.</p>
    /// <p> <b>Important</b> As of June 17, 2019, this parameter is ignored and the value is assumed to be true. The response from this operation always interleaves events from multiple log streams within a log group.</p>
    #[deprecated(
        note = "Starting on June 17, 2019, this parameter will be ignored and the value will be assumed to be true. The response from this operation will always interleave events from multiple log streams within a log group."
    )]
    pub fn get_interleaved(&self) -> &::std::option::Option<bool> {
        self.inner.get_interleaved()
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn unmask(mut self, input: bool) -> Self {
        self.inner = self.inner.unmask(input);
        self
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn set_unmask(mut self, input: ::std::option::Option<bool>) -> Self {
        self.inner = self.inner.set_unmask(input);
        self
    }
    /// <p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>
    /// <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p>
    pub fn get_unmask(&self) -> &::std::option::Option<bool> {
        self.inner.get_unmask()
    }
}