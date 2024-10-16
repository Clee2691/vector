// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::describe_delivery_stream::_describe_delivery_stream_output::DescribeDeliveryStreamOutputBuilder;

pub use crate::operation::describe_delivery_stream::_describe_delivery_stream_input::DescribeDeliveryStreamInputBuilder;

impl DescribeDeliveryStreamInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_delivery_stream::DescribeDeliveryStreamError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.describe_delivery_stream();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `DescribeDeliveryStream`.
///
/// <p>Describes the specified delivery stream and its status. For example, after your delivery stream is created, call <code>DescribeDeliveryStream</code> to see whether the delivery stream is <code>ACTIVE</code> and therefore ready for data to be sent to it. </p>
/// <p>If the status of a delivery stream is <code>CREATING_FAILED</code>, this status doesn't change, and you can't invoke <code>CreateDeliveryStream</code> again on it. However, you can invoke the <code>DeleteDeliveryStream</code> operation to delete it. If the status is <code>DELETING_FAILED</code>, you can force deletion by invoking <code>DeleteDeliveryStream</code> again but with <code>DeleteDeliveryStreamInput$AllowForceDelete</code> set to true.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct DescribeDeliveryStreamFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::describe_delivery_stream::builders::DescribeDeliveryStreamInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput,
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamError,
    > for DescribeDeliveryStreamFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput,
            crate::operation::describe_delivery_stream::DescribeDeliveryStreamError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl DescribeDeliveryStreamFluentBuilder {
    /// Creates a new `DescribeDeliveryStream`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the DescribeDeliveryStream as a reference.
    pub fn as_input(&self) -> &crate::operation::describe_delivery_stream::builders::DescribeDeliveryStreamInputBuilder {
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
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_delivery_stream::DescribeDeliveryStreamError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::describe_delivery_stream::DescribeDeliveryStream::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::describe_delivery_stream::DescribeDeliveryStream::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput,
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamError,
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
    /// <p>The name of the delivery stream.</p>
    pub fn delivery_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.delivery_stream_name(input.into());
        self
    }
    /// <p>The name of the delivery stream.</p>
    pub fn set_delivery_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_delivery_stream_name(input);
        self
    }
    /// <p>The name of the delivery stream.</p>
    pub fn get_delivery_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_delivery_stream_name()
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per delivery stream.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.inner = self.inner.limit(input);
        self
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per delivery stream.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_limit(input);
        self
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per delivery stream.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        self.inner.get_limit()
    }
    /// <p>The ID of the destination to start returning the destination information. Kinesis Data Firehose supports one destination per delivery stream.</p>
    pub fn exclusive_start_destination_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.exclusive_start_destination_id(input.into());
        self
    }
    /// <p>The ID of the destination to start returning the destination information. Kinesis Data Firehose supports one destination per delivery stream.</p>
    pub fn set_exclusive_start_destination_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_exclusive_start_destination_id(input);
        self
    }
    /// <p>The ID of the destination to start returning the destination information. Kinesis Data Firehose supports one destination per delivery stream.</p>
    pub fn get_exclusive_start_destination_id(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_exclusive_start_destination_id()
    }
}