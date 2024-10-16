// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input for GetEndpointAttributes action.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEndpointAttributesInput {
    /// <p>EndpointArn for GetEndpointAttributes input.</p>
    pub endpoint_arn: ::std::option::Option<::std::string::String>,
}
impl GetEndpointAttributesInput {
    /// <p>EndpointArn for GetEndpointAttributes input.</p>
    pub fn endpoint_arn(&self) -> ::std::option::Option<&str> {
        self.endpoint_arn.as_deref()
    }
}
impl GetEndpointAttributesInput {
    /// Creates a new builder-style object to manufacture [`GetEndpointAttributesInput`](crate::operation::get_endpoint_attributes::GetEndpointAttributesInput).
    pub fn builder() -> crate::operation::get_endpoint_attributes::builders::GetEndpointAttributesInputBuilder {
        crate::operation::get_endpoint_attributes::builders::GetEndpointAttributesInputBuilder::default()
    }
}

/// A builder for [`GetEndpointAttributesInput`](crate::operation::get_endpoint_attributes::GetEndpointAttributesInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetEndpointAttributesInputBuilder {
    pub(crate) endpoint_arn: ::std::option::Option<::std::string::String>,
}
impl GetEndpointAttributesInputBuilder {
    /// <p>EndpointArn for GetEndpointAttributes input.</p>
    /// This field is required.
    pub fn endpoint_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>EndpointArn for GetEndpointAttributes input.</p>
    pub fn set_endpoint_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_arn = input;
        self
    }
    /// <p>EndpointArn for GetEndpointAttributes input.</p>
    pub fn get_endpoint_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_arn
    }
    /// Consumes the builder and constructs a [`GetEndpointAttributesInput`](crate::operation::get_endpoint_attributes::GetEndpointAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_endpoint_attributes::GetEndpointAttributesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_endpoint_attributes::GetEndpointAttributesInput {
            endpoint_arn: self.endpoint_arn,
        })
    }
}