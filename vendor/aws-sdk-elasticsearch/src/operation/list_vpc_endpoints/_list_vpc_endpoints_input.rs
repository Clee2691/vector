// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for request parameters to the <code><code>ListVpcEndpoints</code></code> operation.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVpcEndpointsInput {
    /// <p>Identifier to allow retrieval of paginated results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListVpcEndpointsInput {
    /// <p>Identifier to allow retrieval of paginated results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListVpcEndpointsInput {
    /// Creates a new builder-style object to manufacture [`ListVpcEndpointsInput`](crate::operation::list_vpc_endpoints::ListVpcEndpointsInput).
    pub fn builder() -> crate::operation::list_vpc_endpoints::builders::ListVpcEndpointsInputBuilder {
        crate::operation::list_vpc_endpoints::builders::ListVpcEndpointsInputBuilder::default()
    }
}

/// A builder for [`ListVpcEndpointsInput`](crate::operation::list_vpc_endpoints::ListVpcEndpointsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ListVpcEndpointsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListVpcEndpointsInputBuilder {
    /// <p>Identifier to allow retrieval of paginated results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier to allow retrieval of paginated results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Identifier to allow retrieval of paginated results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListVpcEndpointsInput`](crate::operation::list_vpc_endpoints::ListVpcEndpointsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_vpc_endpoints::ListVpcEndpointsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_vpc_endpoints::ListVpcEndpointsInput { next_token: self.next_token })
    }
}