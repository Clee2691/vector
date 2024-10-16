// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::update_stream_mode::_update_stream_mode_output::UpdateStreamModeOutputBuilder;

pub use crate::operation::update_stream_mode::_update_stream_mode_input::UpdateStreamModeInputBuilder;

impl UpdateStreamModeInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::update_stream_mode::UpdateStreamModeOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::update_stream_mode::UpdateStreamModeError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.update_stream_mode();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `UpdateStreamMode`.
///
/// <p> Updates the capacity mode of the data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data stream. </p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct UpdateStreamModeFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::update_stream_mode::builders::UpdateStreamModeInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::update_stream_mode::UpdateStreamModeOutput,
        crate::operation::update_stream_mode::UpdateStreamModeError,
    > for UpdateStreamModeFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::update_stream_mode::UpdateStreamModeOutput,
            crate::operation::update_stream_mode::UpdateStreamModeError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl UpdateStreamModeFluentBuilder {
    /// Creates a new `UpdateStreamMode`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the UpdateStreamMode as a reference.
    pub fn as_input(&self) -> &crate::operation::update_stream_mode::builders::UpdateStreamModeInputBuilder {
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
        crate::operation::update_stream_mode::UpdateStreamModeOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::update_stream_mode::UpdateStreamModeError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::update_stream_mode::UpdateStreamMode::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::update_stream_mode::UpdateStreamMode::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::update_stream_mode::UpdateStreamModeOutput,
        crate::operation::update_stream_mode::UpdateStreamModeError,
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
    /// <p> Specifies the ARN of the data stream whose capacity mode you want to update. </p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.stream_arn(input.into());
        self
    }
    /// <p> Specifies the ARN of the data stream whose capacity mode you want to update. </p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_stream_arn(input);
        self
    }
    /// <p> Specifies the ARN of the data stream whose capacity mode you want to update. </p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_stream_arn()
    }
    /// <p> Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams. </p>
    pub fn stream_mode_details(mut self, input: crate::types::StreamModeDetails) -> Self {
        self.inner = self.inner.stream_mode_details(input);
        self
    }
    /// <p> Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams. </p>
    pub fn set_stream_mode_details(mut self, input: ::std::option::Option<crate::types::StreamModeDetails>) -> Self {
        self.inner = self.inner.set_stream_mode_details(input);
        self
    }
    /// <p> Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams. </p>
    pub fn get_stream_mode_details(&self) -> &::std::option::Option<crate::types::StreamModeDetails> {
        self.inner.get_stream_mode_details()
    }
}