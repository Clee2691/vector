// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`FilterLogEvents`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`log_group_name(impl Into<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::log_group_name) / [`set_log_group_name(Option<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_log_group_name):<br>required: **false**<br><p>The name of the log group to search.</p> <note>   <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>  </note><br>
    ///   - [`log_group_identifier(impl Into<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::log_group_identifier) / [`set_log_group_identifier(Option<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_log_group_identifier):<br>required: **false**<br><p>Specify either the name or ARN of the log group to view log events from. If the log group is in a source account and you are using a monitoring account, you must use the log group ARN.</p> <note>   <p> You must include either <code>logGroupIdentifier</code> or <code>logGroupName</code>, but not both. </p>  </note><br>
    ///   - [`log_stream_names(impl Into<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::log_stream_names) / [`set_log_stream_names(Option<Vec::<String>>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_log_stream_names):<br>required: **false**<br><p>Filters the results to only logs from the log streams in this list.</p>  <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p><br>
    ///   - [`log_stream_name_prefix(impl Into<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::log_stream_name_prefix) / [`set_log_stream_name_prefix(Option<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_log_stream_name_prefix):<br>required: **false**<br><p>Filters the results to include only events from log streams that have names starting with this prefix.</p>  <p>If you specify a value for both <code>logStreamNamePrefix</code> and <code>logStreamNames</code>, but the value for <code>logStreamNamePrefix</code> does not match any log stream names specified in <code>logStreamNames</code>, the action returns an <code>InvalidParameterException</code> error.</p><br>
    ///   - [`start_time(i64)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::start_time) / [`set_start_time(Option<i64>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_start_time):<br>required: **false**<br><p>The start of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp before this time are not returned.</p><br>
    ///   - [`end_time(i64)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::end_time) / [`set_end_time(Option<i64>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_end_time):<br>required: **false**<br><p>The end of the time range, expressed as the number of milliseconds after <code>Jan 1, 1970 00:00:00 UTC</code>. Events with a timestamp later than this time are not returned.</p><br>
    ///   - [`filter_pattern(impl Into<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::filter_pattern) / [`set_filter_pattern(Option<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_filter_pattern):<br>required: **false**<br><p>The filter pattern to use. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>  <p>If not provided, all the events are matched.</p><br>
    ///   - [`next_token(impl Into<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_next_token):<br>required: **false**<br><p>The token for the next set of events to return. (You received this token from a previous call.)</p><br>
    ///   - [`limit(i32)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::limit) / [`set_limit(Option<i32>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_limit):<br>required: **false**<br><p>The maximum number of events to return. The default is 10,000 events.</p><br>
    ///   - [`interleaved(bool)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::interleaved) / [`set_interleaved(Option<bool>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_interleaved):<br>required: **false**<br><p>If the value is true, the operation attempts to provide responses that contain events from multiple log streams within the log group, interleaved in a single response. If the value is false, all the matched log events in the first log stream are searched first, then those in the next log stream, and so on.</p>  <p> <b>Important</b> As of June 17, 2019, this parameter is ignored and the value is assumed to be true. The response from this operation always interleaves events from multiple log streams within a log group.</p><br>
    ///   - [`unmask(bool)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::unmask) / [`set_unmask(Option<bool>)`](crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::set_unmask):<br>required: **false**<br><p>Specify <code>true</code> to display the log event fields with all sensitive data unmasked and visible. The default is <code>false</code>.</p>  <p>To use this operation with this parameter, you must be signed into an account with the <code>logs:Unmask</code> permission.</p><br>
    /// - On success, responds with [`FilterLogEventsOutput`](crate::operation::filter_log_events::FilterLogEventsOutput) with field(s):
    ///   - [`events(Option<Vec::<FilteredLogEvent>>)`](crate::operation::filter_log_events::FilterLogEventsOutput::events): <p>The matched events.</p>
    ///   - [`searched_log_streams(Option<Vec::<SearchedLogStream>>)`](crate::operation::filter_log_events::FilterLogEventsOutput::searched_log_streams): <p> <b>Important</b> As of May 15, 2020, this parameter is no longer supported. This parameter returns an empty list.</p>  <p>Indicates which log streams have been searched and whether each has been searched completely.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::filter_log_events::FilterLogEventsOutput::next_token): <p>The token to use when requesting the next set of items. The token expires after 24 hours.</p>
    /// - On failure, responds with [`SdkError<FilterLogEventsError>`](crate::operation::filter_log_events::FilterLogEventsError)
    pub fn filter_log_events(&self) -> crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder {
        crate::operation::filter_log_events::builders::FilterLogEventsFluentBuilder::new(self.handle.clone())
    }
}