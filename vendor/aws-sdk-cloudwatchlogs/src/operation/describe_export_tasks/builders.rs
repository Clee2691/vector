// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::describe_export_tasks::_describe_export_tasks_output::DescribeExportTasksOutputBuilder;

pub use crate::operation::describe_export_tasks::_describe_export_tasks_input::DescribeExportTasksInputBuilder;

impl DescribeExportTasksInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::describe_export_tasks::DescribeExportTasksOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_export_tasks::DescribeExportTasksError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.describe_export_tasks();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `DescribeExportTasks`.
///
/// <p>Lists the specified export tasks. You can list all your export tasks or filter the results based on task ID or task status.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct DescribeExportTasksFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::describe_export_tasks::builders::DescribeExportTasksInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::describe_export_tasks::DescribeExportTasksOutput,
        crate::operation::describe_export_tasks::DescribeExportTasksError,
    > for DescribeExportTasksFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::describe_export_tasks::DescribeExportTasksOutput,
            crate::operation::describe_export_tasks::DescribeExportTasksError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl DescribeExportTasksFluentBuilder {
    /// Creates a new `DescribeExportTasks`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the DescribeExportTasks as a reference.
    pub fn as_input(&self) -> &crate::operation::describe_export_tasks::builders::DescribeExportTasksInputBuilder {
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
        crate::operation::describe_export_tasks::DescribeExportTasksOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_export_tasks::DescribeExportTasksError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::describe_export_tasks::DescribeExportTasks::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::describe_export_tasks::DescribeExportTasks::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::describe_export_tasks::DescribeExportTasksOutput,
        crate::operation::describe_export_tasks::DescribeExportTasksError,
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
    /// <p>The ID of the export task. Specifying a task ID filters the results to one or zero export tasks.</p>
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.task_id(input.into());
        self
    }
    /// <p>The ID of the export task. Specifying a task ID filters the results to one or zero export tasks.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_task_id(input);
        self
    }
    /// <p>The ID of the export task. Specifying a task ID filters the results to one or zero export tasks.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_task_id()
    }
    /// <p>The status code of the export task. Specifying a status code filters the results to zero or more export tasks.</p>
    pub fn status_code(mut self, input: crate::types::ExportTaskStatusCode) -> Self {
        self.inner = self.inner.status_code(input);
        self
    }
    /// <p>The status code of the export task. Specifying a status code filters the results to zero or more export tasks.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<crate::types::ExportTaskStatusCode>) -> Self {
        self.inner = self.inner.set_status_code(input);
        self
    }
    /// <p>The status code of the export task. Specifying a status code filters the results to zero or more export tasks.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<crate::types::ExportTaskStatusCode> {
        self.inner.get_status_code()
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.next_token(input.into());
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_next_token(input);
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_next_token()
    }
    /// <p>The maximum number of items returned. If you don't specify a value, the default is up to 50 items.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.inner = self.inner.limit(input);
        self
    }
    /// <p>The maximum number of items returned. If you don't specify a value, the default is up to 50 items.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_limit(input);
        self
    }
    /// <p>The maximum number of items returned. If you don't specify a value, the default is up to 50 items.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        self.inner.get_limit()
    }
}