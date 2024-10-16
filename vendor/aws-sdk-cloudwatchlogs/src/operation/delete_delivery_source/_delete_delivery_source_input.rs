// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDeliverySourceInput {
    /// <p>The name of the delivery source that you want to delete.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteDeliverySourceInput {
    /// <p>The name of the delivery source that you want to delete.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteDeliverySourceInput {
    /// Creates a new builder-style object to manufacture [`DeleteDeliverySourceInput`](crate::operation::delete_delivery_source::DeleteDeliverySourceInput).
    pub fn builder() -> crate::operation::delete_delivery_source::builders::DeleteDeliverySourceInputBuilder {
        crate::operation::delete_delivery_source::builders::DeleteDeliverySourceInputBuilder::default()
    }
}

/// A builder for [`DeleteDeliverySourceInput`](crate::operation::delete_delivery_source::DeleteDeliverySourceInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteDeliverySourceInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteDeliverySourceInputBuilder {
    /// <p>The name of the delivery source that you want to delete.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the delivery source that you want to delete.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the delivery source that you want to delete.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteDeliverySourceInput`](crate::operation::delete_delivery_source::DeleteDeliverySourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_delivery_source::DeleteDeliverySourceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_delivery_source::DeleteDeliverySourceInput { name: self.name })
    }
}