// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::update_vpc_endpoint::_update_vpc_endpoint_output::UpdateVpcEndpointOutputBuilder;

pub use crate::operation::update_vpc_endpoint::_update_vpc_endpoint_input::UpdateVpcEndpointInputBuilder;

impl UpdateVpcEndpointInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::update_vpc_endpoint::UpdateVpcEndpointOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::update_vpc_endpoint::UpdateVpcEndpointError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.update_vpc_endpoint();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `UpdateVpcEndpoint`.
///
/// <p>Modifies an Amazon OpenSearch Service-managed interface VPC endpoint.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct UpdateVpcEndpointFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::update_vpc_endpoint::builders::UpdateVpcEndpointInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::update_vpc_endpoint::UpdateVpcEndpointOutput,
        crate::operation::update_vpc_endpoint::UpdateVpcEndpointError,
    > for UpdateVpcEndpointFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::update_vpc_endpoint::UpdateVpcEndpointOutput,
            crate::operation::update_vpc_endpoint::UpdateVpcEndpointError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl UpdateVpcEndpointFluentBuilder {
    /// Creates a new `UpdateVpcEndpoint`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the UpdateVpcEndpoint as a reference.
    pub fn as_input(&self) -> &crate::operation::update_vpc_endpoint::builders::UpdateVpcEndpointInputBuilder {
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
        crate::operation::update_vpc_endpoint::UpdateVpcEndpointOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::update_vpc_endpoint::UpdateVpcEndpointError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::update_vpc_endpoint::UpdateVpcEndpoint::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::update_vpc_endpoint::UpdateVpcEndpoint::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::update_vpc_endpoint::UpdateVpcEndpointOutput,
        crate::operation::update_vpc_endpoint::UpdateVpcEndpointError,
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
    /// <p>Unique identifier of the VPC endpoint to be updated.</p>
    pub fn vpc_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.vpc_endpoint_id(input.into());
        self
    }
    /// <p>Unique identifier of the VPC endpoint to be updated.</p>
    pub fn set_vpc_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_vpc_endpoint_id(input);
        self
    }
    /// <p>Unique identifier of the VPC endpoint to be updated.</p>
    pub fn get_vpc_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_vpc_endpoint_id()
    }
    /// <p>The security groups and/or subnets to add, remove, or modify.</p>
    pub fn vpc_options(mut self, input: crate::types::VpcOptions) -> Self {
        self.inner = self.inner.vpc_options(input);
        self
    }
    /// <p>The security groups and/or subnets to add, remove, or modify.</p>
    pub fn set_vpc_options(mut self, input: ::std::option::Option<crate::types::VpcOptions>) -> Self {
        self.inner = self.inner.set_vpc_options(input);
        self
    }
    /// <p>The security groups and/or subnets to add, remove, or modify.</p>
    pub fn get_vpc_options(&self) -> &::std::option::Option<crate::types::VpcOptions> {
        self.inner.get_vpc_options()
    }
}