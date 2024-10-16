// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::unsubscribe::_unsubscribe_output::UnsubscribeOutputBuilder;

pub use crate::operation::unsubscribe::_unsubscribe_input::UnsubscribeInputBuilder;

impl UnsubscribeInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::unsubscribe::UnsubscribeOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::unsubscribe::UnsubscribeError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.unsubscribe();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `Unsubscribe`.
///
/// <p>Deletes a subscription. If the subscription requires authentication for deletion, only the owner of the subscription or the topic's owner can unsubscribe, and an Amazon Web Services signature is required. If the <code>Unsubscribe</code> call does not require authentication and the requester is not the subscription owner, a final cancellation message is delivered to the endpoint, so that the endpoint owner can easily resubscribe to the topic if the <code>Unsubscribe</code> request was unintended.</p> <note>
/// <p>Amazon SQS queue subscriptions require authentication for deletion. Only the owner of the subscription, or the owner of the topic can unsubscribe using the required Amazon Web Services signature.</p>
/// </note>
/// <p>This action is throttled at 100 transactions per second (TPS).</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct UnsubscribeFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::unsubscribe::builders::UnsubscribeInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::unsubscribe::UnsubscribeOutput,
        crate::operation::unsubscribe::UnsubscribeError,
    > for UnsubscribeFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::unsubscribe::UnsubscribeOutput,
            crate::operation::unsubscribe::UnsubscribeError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl UnsubscribeFluentBuilder {
    /// Creates a new `Unsubscribe`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the Unsubscribe as a reference.
    pub fn as_input(&self) -> &crate::operation::unsubscribe::builders::UnsubscribeInputBuilder {
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
        crate::operation::unsubscribe::UnsubscribeOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::unsubscribe::UnsubscribeError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::unsubscribe::Unsubscribe::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::unsubscribe::Unsubscribe::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::unsubscribe::UnsubscribeOutput,
        crate::operation::unsubscribe::UnsubscribeError,
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
    /// <p>The ARN of the subscription to be deleted.</p>
    pub fn subscription_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.subscription_arn(input.into());
        self
    }
    /// <p>The ARN of the subscription to be deleted.</p>
    pub fn set_subscription_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_subscription_arn(input);
        self
    }
    /// <p>The ARN of the subscription to be deleted.</p>
    pub fn get_subscription_arn(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_subscription_arn()
    }
}