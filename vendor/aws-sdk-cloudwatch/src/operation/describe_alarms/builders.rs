// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::describe_alarms::_describe_alarms_output::DescribeAlarmsOutputBuilder;

pub use crate::operation::describe_alarms::_describe_alarms_input::DescribeAlarmsInputBuilder;

impl DescribeAlarmsInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::describe_alarms::DescribeAlarmsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_alarms::DescribeAlarmsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.describe_alarms();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `DescribeAlarms`.
///
/// <p>Retrieves the specified alarms. You can filter the results by specifying a prefix for the alarm name, the alarm state, or a prefix for any action.</p>
/// <p>To use this operation and return information about composite alarms, you must be signed on with the <code>cloudwatch:DescribeAlarms</code> permission that is scoped to <code>*</code>. You can't return information about composite alarms if your <code>cloudwatch:DescribeAlarms</code> permission has a narrower scope.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct DescribeAlarmsFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::describe_alarms::builders::DescribeAlarmsInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::describe_alarms::DescribeAlarmsOutput,
        crate::operation::describe_alarms::DescribeAlarmsError,
    > for DescribeAlarmsFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::describe_alarms::DescribeAlarmsOutput,
            crate::operation::describe_alarms::DescribeAlarmsError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl DescribeAlarmsFluentBuilder {
    /// Creates a new `DescribeAlarms`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the DescribeAlarms as a reference.
    pub fn as_input(&self) -> &crate::operation::describe_alarms::builders::DescribeAlarmsInputBuilder {
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
        crate::operation::describe_alarms::DescribeAlarmsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_alarms::DescribeAlarmsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::describe_alarms::DescribeAlarms::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::describe_alarms::DescribeAlarms::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::describe_alarms::DescribeAlarmsOutput,
        crate::operation::describe_alarms::DescribeAlarmsError,
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
    /// Paginators are used by calling [`send().await`](crate::operation::describe_alarms::paginator::DescribeAlarmsPaginator::send) which returns a [`PaginationStream`](aws_smithy_async::future::pagination_stream::PaginationStream).
    pub fn into_paginator(self) -> crate::operation::describe_alarms::paginator::DescribeAlarmsPaginator {
        crate::operation::describe_alarms::paginator::DescribeAlarmsPaginator::new(self.handle, self.inner)
    }
    /// Appends an item to `AlarmNames`.
    ///
    /// To override the contents of this collection use [`set_alarm_names`](Self::set_alarm_names).
    ///
    /// <p>The names of the alarms to retrieve information about.</p>
    pub fn alarm_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.alarm_names(input.into());
        self
    }
    /// <p>The names of the alarms to retrieve information about.</p>
    pub fn set_alarm_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inner = self.inner.set_alarm_names(input);
        self
    }
    /// <p>The names of the alarms to retrieve information about.</p>
    pub fn get_alarm_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        self.inner.get_alarm_names()
    }
    /// <p>An alarm name prefix. If you specify this parameter, you receive information about all alarms that have names that start with this prefix.</p>
    /// <p>If this parameter is specified, you cannot specify <code>AlarmNames</code>.</p>
    pub fn alarm_name_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.alarm_name_prefix(input.into());
        self
    }
    /// <p>An alarm name prefix. If you specify this parameter, you receive information about all alarms that have names that start with this prefix.</p>
    /// <p>If this parameter is specified, you cannot specify <code>AlarmNames</code>.</p>
    pub fn set_alarm_name_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_alarm_name_prefix(input);
        self
    }
    /// <p>An alarm name prefix. If you specify this parameter, you receive information about all alarms that have names that start with this prefix.</p>
    /// <p>If this parameter is specified, you cannot specify <code>AlarmNames</code>.</p>
    pub fn get_alarm_name_prefix(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_alarm_name_prefix()
    }
    /// Appends an item to `AlarmTypes`.
    ///
    /// To override the contents of this collection use [`set_alarm_types`](Self::set_alarm_types).
    ///
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned, even if composite alarms exist in the account.</p>
    /// <p>For example, if you omit this parameter or specify <code>MetricAlarms</code>, the operation returns only a list of metric alarms. It does not return any composite alarms, even if composite alarms exist in the account.</p>
    /// <p>If you specify <code>CompositeAlarms</code>, the operation returns only a list of composite alarms, and does not return any metric alarms.</p>
    pub fn alarm_types(mut self, input: crate::types::AlarmType) -> Self {
        self.inner = self.inner.alarm_types(input);
        self
    }
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned, even if composite alarms exist in the account.</p>
    /// <p>For example, if you omit this parameter or specify <code>MetricAlarms</code>, the operation returns only a list of metric alarms. It does not return any composite alarms, even if composite alarms exist in the account.</p>
    /// <p>If you specify <code>CompositeAlarms</code>, the operation returns only a list of composite alarms, and does not return any metric alarms.</p>
    pub fn set_alarm_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AlarmType>>) -> Self {
        self.inner = self.inner.set_alarm_types(input);
        self
    }
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned, even if composite alarms exist in the account.</p>
    /// <p>For example, if you omit this parameter or specify <code>MetricAlarms</code>, the operation returns only a list of metric alarms. It does not return any composite alarms, even if composite alarms exist in the account.</p>
    /// <p>If you specify <code>CompositeAlarms</code>, the operation returns only a list of composite alarms, and does not return any metric alarms.</p>
    pub fn get_alarm_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AlarmType>> {
        self.inner.get_alarm_types()
    }
    /// <p>If you use this parameter and specify the name of a composite alarm, the operation returns information about the "children" alarms of the alarm you specify. These are the metric alarms and composite alarms referenced in the <code>AlarmRule</code> field of the composite alarm that you specify in <code>ChildrenOfAlarmName</code>. Information about the composite alarm that you name in <code>ChildrenOfAlarmName</code> is not returned.</p>
    /// <p>If you specify <code>ChildrenOfAlarmName</code>, you cannot specify any other parameters in the request except for <code>MaxRecords</code> and <code>NextToken</code>. If you do so, you receive a validation error.</p> <note>
    /// <p>Only the <code>Alarm Name</code>, <code>ARN</code>, <code>StateValue</code> (OK/ALARM/INSUFFICIENT_DATA), and <code>StateUpdatedTimestamp</code> information are returned by this operation when you use this parameter. To get complete information about these alarms, perform another <code>DescribeAlarms</code> operation and specify the parent alarm names in the <code>AlarmNames</code> parameter.</p>
    /// </note>
    pub fn children_of_alarm_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.children_of_alarm_name(input.into());
        self
    }
    /// <p>If you use this parameter and specify the name of a composite alarm, the operation returns information about the "children" alarms of the alarm you specify. These are the metric alarms and composite alarms referenced in the <code>AlarmRule</code> field of the composite alarm that you specify in <code>ChildrenOfAlarmName</code>. Information about the composite alarm that you name in <code>ChildrenOfAlarmName</code> is not returned.</p>
    /// <p>If you specify <code>ChildrenOfAlarmName</code>, you cannot specify any other parameters in the request except for <code>MaxRecords</code> and <code>NextToken</code>. If you do so, you receive a validation error.</p> <note>
    /// <p>Only the <code>Alarm Name</code>, <code>ARN</code>, <code>StateValue</code> (OK/ALARM/INSUFFICIENT_DATA), and <code>StateUpdatedTimestamp</code> information are returned by this operation when you use this parameter. To get complete information about these alarms, perform another <code>DescribeAlarms</code> operation and specify the parent alarm names in the <code>AlarmNames</code> parameter.</p>
    /// </note>
    pub fn set_children_of_alarm_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_children_of_alarm_name(input);
        self
    }
    /// <p>If you use this parameter and specify the name of a composite alarm, the operation returns information about the "children" alarms of the alarm you specify. These are the metric alarms and composite alarms referenced in the <code>AlarmRule</code> field of the composite alarm that you specify in <code>ChildrenOfAlarmName</code>. Information about the composite alarm that you name in <code>ChildrenOfAlarmName</code> is not returned.</p>
    /// <p>If you specify <code>ChildrenOfAlarmName</code>, you cannot specify any other parameters in the request except for <code>MaxRecords</code> and <code>NextToken</code>. If you do so, you receive a validation error.</p> <note>
    /// <p>Only the <code>Alarm Name</code>, <code>ARN</code>, <code>StateValue</code> (OK/ALARM/INSUFFICIENT_DATA), and <code>StateUpdatedTimestamp</code> information are returned by this operation when you use this parameter. To get complete information about these alarms, perform another <code>DescribeAlarms</code> operation and specify the parent alarm names in the <code>AlarmNames</code> parameter.</p>
    /// </note>
    pub fn get_children_of_alarm_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_children_of_alarm_name()
    }
    /// <p>If you use this parameter and specify the name of a metric or composite alarm, the operation returns information about the "parent" alarms of the alarm you specify. These are the composite alarms that have <code>AlarmRule</code> parameters that reference the alarm named in <code>ParentsOfAlarmName</code>. Information about the alarm that you specify in <code>ParentsOfAlarmName</code> is not returned.</p>
    /// <p>If you specify <code>ParentsOfAlarmName</code>, you cannot specify any other parameters in the request except for <code>MaxRecords</code> and <code>NextToken</code>. If you do so, you receive a validation error.</p> <note>
    /// <p>Only the Alarm Name and ARN are returned by this operation when you use this parameter. To get complete information about these alarms, perform another <code>DescribeAlarms</code> operation and specify the parent alarm names in the <code>AlarmNames</code> parameter.</p>
    /// </note>
    pub fn parents_of_alarm_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.parents_of_alarm_name(input.into());
        self
    }
    /// <p>If you use this parameter and specify the name of a metric or composite alarm, the operation returns information about the "parent" alarms of the alarm you specify. These are the composite alarms that have <code>AlarmRule</code> parameters that reference the alarm named in <code>ParentsOfAlarmName</code>. Information about the alarm that you specify in <code>ParentsOfAlarmName</code> is not returned.</p>
    /// <p>If you specify <code>ParentsOfAlarmName</code>, you cannot specify any other parameters in the request except for <code>MaxRecords</code> and <code>NextToken</code>. If you do so, you receive a validation error.</p> <note>
    /// <p>Only the Alarm Name and ARN are returned by this operation when you use this parameter. To get complete information about these alarms, perform another <code>DescribeAlarms</code> operation and specify the parent alarm names in the <code>AlarmNames</code> parameter.</p>
    /// </note>
    pub fn set_parents_of_alarm_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_parents_of_alarm_name(input);
        self
    }
    /// <p>If you use this parameter and specify the name of a metric or composite alarm, the operation returns information about the "parent" alarms of the alarm you specify. These are the composite alarms that have <code>AlarmRule</code> parameters that reference the alarm named in <code>ParentsOfAlarmName</code>. Information about the alarm that you specify in <code>ParentsOfAlarmName</code> is not returned.</p>
    /// <p>If you specify <code>ParentsOfAlarmName</code>, you cannot specify any other parameters in the request except for <code>MaxRecords</code> and <code>NextToken</code>. If you do so, you receive a validation error.</p> <note>
    /// <p>Only the Alarm Name and ARN are returned by this operation when you use this parameter. To get complete information about these alarms, perform another <code>DescribeAlarms</code> operation and specify the parent alarm names in the <code>AlarmNames</code> parameter.</p>
    /// </note>
    pub fn get_parents_of_alarm_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_parents_of_alarm_name()
    }
    /// <p>Specify this parameter to receive information only about alarms that are currently in the state that you specify.</p>
    pub fn state_value(mut self, input: crate::types::StateValue) -> Self {
        self.inner = self.inner.state_value(input);
        self
    }
    /// <p>Specify this parameter to receive information only about alarms that are currently in the state that you specify.</p>
    pub fn set_state_value(mut self, input: ::std::option::Option<crate::types::StateValue>) -> Self {
        self.inner = self.inner.set_state_value(input);
        self
    }
    /// <p>Specify this parameter to receive information only about alarms that are currently in the state that you specify.</p>
    pub fn get_state_value(&self) -> &::std::option::Option<crate::types::StateValue> {
        self.inner.get_state_value()
    }
    /// <p>Use this parameter to filter the results of the operation to only those alarms that use a certain alarm action. For example, you could specify the ARN of an SNS topic to find all alarms that send notifications to that topic.</p>
    pub fn action_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.action_prefix(input.into());
        self
    }
    /// <p>Use this parameter to filter the results of the operation to only those alarms that use a certain alarm action. For example, you could specify the ARN of an SNS topic to find all alarms that send notifications to that topic.</p>
    pub fn set_action_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_action_prefix(input);
        self
    }
    /// <p>Use this parameter to filter the results of the operation to only those alarms that use a certain alarm action. For example, you could specify the ARN of an SNS topic to find all alarms that send notifications to that topic.</p>
    pub fn get_action_prefix(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_action_prefix()
    }
    /// <p>The maximum number of alarm descriptions to retrieve.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.inner = self.inner.max_records(input);
        self
    }
    /// <p>The maximum number of alarm descriptions to retrieve.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_max_records(input);
        self
    }
    /// <p>The maximum number of alarm descriptions to retrieve.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        self.inner.get_max_records()
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.next_token(input.into());
        self
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_next_token(input);
        self
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_next_token()
    }
}