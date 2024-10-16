// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::list_managed_insight_rules::_list_managed_insight_rules_output::ListManagedInsightRulesOutputBuilder;

pub use crate::operation::list_managed_insight_rules::_list_managed_insight_rules_input::ListManagedInsightRulesInputBuilder;

impl ListManagedInsightRulesInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::list_managed_insight_rules::ListManagedInsightRulesOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::list_managed_insight_rules::ListManagedInsightRulesError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.list_managed_insight_rules();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `ListManagedInsightRules`.
///
/// <p> Returns a list that contains the number of managed Contributor Insights rules in your account. </p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct ListManagedInsightRulesFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::list_managed_insight_rules::builders::ListManagedInsightRulesInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::list_managed_insight_rules::ListManagedInsightRulesOutput,
        crate::operation::list_managed_insight_rules::ListManagedInsightRulesError,
    > for ListManagedInsightRulesFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::list_managed_insight_rules::ListManagedInsightRulesOutput,
            crate::operation::list_managed_insight_rules::ListManagedInsightRulesError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl ListManagedInsightRulesFluentBuilder {
    /// Creates a new `ListManagedInsightRules`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the ListManagedInsightRules as a reference.
    pub fn as_input(&self) -> &crate::operation::list_managed_insight_rules::builders::ListManagedInsightRulesInputBuilder {
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
        crate::operation::list_managed_insight_rules::ListManagedInsightRulesOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::list_managed_insight_rules::ListManagedInsightRulesError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::list_managed_insight_rules::ListManagedInsightRules::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::list_managed_insight_rules::ListManagedInsightRules::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::list_managed_insight_rules::ListManagedInsightRulesOutput,
        crate::operation::list_managed_insight_rules::ListManagedInsightRulesError,
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
    /// Paginators are used by calling [`send().await`](crate::operation::list_managed_insight_rules::paginator::ListManagedInsightRulesPaginator::send) which returns a [`PaginationStream`](aws_smithy_async::future::pagination_stream::PaginationStream).
    pub fn into_paginator(self) -> crate::operation::list_managed_insight_rules::paginator::ListManagedInsightRulesPaginator {
        crate::operation::list_managed_insight_rules::paginator::ListManagedInsightRulesPaginator::new(self.handle, self.inner)
    }
    /// <p> The ARN of an Amazon Web Services resource that has managed Contributor Insights rules. </p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.resource_arn(input.into());
        self
    }
    /// <p> The ARN of an Amazon Web Services resource that has managed Contributor Insights rules. </p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_resource_arn(input);
        self
    }
    /// <p> The ARN of an Amazon Web Services resource that has managed Contributor Insights rules. </p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_resource_arn()
    }
    /// <p> Include this value to get the next set of rules if the value was returned by the previous operation. </p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.next_token(input.into());
        self
    }
    /// <p> Include this value to get the next set of rules if the value was returned by the previous operation. </p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_next_token(input);
        self
    }
    /// <p> Include this value to get the next set of rules if the value was returned by the previous operation. </p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_next_token()
    }
    /// <p> The maximum number of results to return in one operation. If you omit this parameter, the default number is used. The default number is <code>100</code>. </p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.inner = self.inner.max_results(input);
        self
    }
    /// <p> The maximum number of results to return in one operation. If you omit this parameter, the default number is used. The default number is <code>100</code>. </p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_max_results(input);
        self
    }
    /// <p> The maximum number of results to return in one operation. If you omit this parameter, the default number is used. The default number is <code>100</code>. </p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        self.inner.get_max_results()
    }
}