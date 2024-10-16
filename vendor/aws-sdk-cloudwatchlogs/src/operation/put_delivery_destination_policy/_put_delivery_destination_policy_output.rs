// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutDeliveryDestinationPolicyOutput {
    /// <p>The contents of the policy that you just created.</p>
    pub policy: ::std::option::Option<crate::types::Policy>,
    _request_id: Option<String>,
}
impl PutDeliveryDestinationPolicyOutput {
    /// <p>The contents of the policy that you just created.</p>
    pub fn policy(&self) -> ::std::option::Option<&crate::types::Policy> {
        self.policy.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutDeliveryDestinationPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutDeliveryDestinationPolicyOutput {
    /// Creates a new builder-style object to manufacture [`PutDeliveryDestinationPolicyOutput`](crate::operation::put_delivery_destination_policy::PutDeliveryDestinationPolicyOutput).
    pub fn builder() -> crate::operation::put_delivery_destination_policy::builders::PutDeliveryDestinationPolicyOutputBuilder {
        crate::operation::put_delivery_destination_policy::builders::PutDeliveryDestinationPolicyOutputBuilder::default()
    }
}

/// A builder for [`PutDeliveryDestinationPolicyOutput`](crate::operation::put_delivery_destination_policy::PutDeliveryDestinationPolicyOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutDeliveryDestinationPolicyOutputBuilder {
    pub(crate) policy: ::std::option::Option<crate::types::Policy>,
    _request_id: Option<String>,
}
impl PutDeliveryDestinationPolicyOutputBuilder {
    /// <p>The contents of the policy that you just created.</p>
    pub fn policy(mut self, input: crate::types::Policy) -> Self {
        self.policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The contents of the policy that you just created.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<crate::types::Policy>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The contents of the policy that you just created.</p>
    pub fn get_policy(&self) -> &::std::option::Option<crate::types::Policy> {
        &self.policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutDeliveryDestinationPolicyOutput`](crate::operation::put_delivery_destination_policy::PutDeliveryDestinationPolicyOutput).
    pub fn build(self) -> crate::operation::put_delivery_destination_policy::PutDeliveryDestinationPolicyOutput {
        crate::operation::put_delivery_destination_policy::PutDeliveryDestinationPolicyOutput {
            policy: self.policy,
            _request_id: self._request_id,
        }
    }
}