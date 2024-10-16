// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDeliverySourceOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteDeliverySourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteDeliverySourceOutput {
    /// Creates a new builder-style object to manufacture [`DeleteDeliverySourceOutput`](crate::operation::delete_delivery_source::DeleteDeliverySourceOutput).
    pub fn builder() -> crate::operation::delete_delivery_source::builders::DeleteDeliverySourceOutputBuilder {
        crate::operation::delete_delivery_source::builders::DeleteDeliverySourceOutputBuilder::default()
    }
}

/// A builder for [`DeleteDeliverySourceOutput`](crate::operation::delete_delivery_source::DeleteDeliverySourceOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteDeliverySourceOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteDeliverySourceOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteDeliverySourceOutput`](crate::operation::delete_delivery_source::DeleteDeliverySourceOutput).
    pub fn build(self) -> crate::operation::delete_delivery_source::DeleteDeliverySourceOutput {
        crate::operation::delete_delivery_source::DeleteDeliverySourceOutput {
            _request_id: self._request_id,
        }
    }
}