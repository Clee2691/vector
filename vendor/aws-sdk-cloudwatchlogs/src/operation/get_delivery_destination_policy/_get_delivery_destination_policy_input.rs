// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeliveryDestinationPolicyInput {
    /// <p>The name of the delivery destination that you want to retrieve the policy of.</p>
    pub delivery_destination_name: ::std::option::Option<::std::string::String>,
}
impl GetDeliveryDestinationPolicyInput {
    /// <p>The name of the delivery destination that you want to retrieve the policy of.</p>
    pub fn delivery_destination_name(&self) -> ::std::option::Option<&str> {
        self.delivery_destination_name.as_deref()
    }
}
impl GetDeliveryDestinationPolicyInput {
    /// Creates a new builder-style object to manufacture [`GetDeliveryDestinationPolicyInput`](crate::operation::get_delivery_destination_policy::GetDeliveryDestinationPolicyInput).
    pub fn builder() -> crate::operation::get_delivery_destination_policy::builders::GetDeliveryDestinationPolicyInputBuilder {
        crate::operation::get_delivery_destination_policy::builders::GetDeliveryDestinationPolicyInputBuilder::default()
    }
}

/// A builder for [`GetDeliveryDestinationPolicyInput`](crate::operation::get_delivery_destination_policy::GetDeliveryDestinationPolicyInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetDeliveryDestinationPolicyInputBuilder {
    pub(crate) delivery_destination_name: ::std::option::Option<::std::string::String>,
}
impl GetDeliveryDestinationPolicyInputBuilder {
    /// <p>The name of the delivery destination that you want to retrieve the policy of.</p>
    /// This field is required.
    pub fn delivery_destination_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_destination_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the delivery destination that you want to retrieve the policy of.</p>
    pub fn set_delivery_destination_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_destination_name = input;
        self
    }
    /// <p>The name of the delivery destination that you want to retrieve the policy of.</p>
    pub fn get_delivery_destination_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_destination_name
    }
    /// Consumes the builder and constructs a [`GetDeliveryDestinationPolicyInput`](crate::operation::get_delivery_destination_policy::GetDeliveryDestinationPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_delivery_destination_policy::GetDeliveryDestinationPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_delivery_destination_policy::GetDeliveryDestinationPolicyInput {
            delivery_destination_name: self.delivery_destination_name,
        })
    }
}