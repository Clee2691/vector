// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopDeliveryStreamEncryptionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for StopDeliveryStreamEncryptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopDeliveryStreamEncryptionOutput {
    /// Creates a new builder-style object to manufacture [`StopDeliveryStreamEncryptionOutput`](crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput).
    pub fn builder() -> crate::operation::stop_delivery_stream_encryption::builders::StopDeliveryStreamEncryptionOutputBuilder {
        crate::operation::stop_delivery_stream_encryption::builders::StopDeliveryStreamEncryptionOutputBuilder::default()
    }
}

/// A builder for [`StopDeliveryStreamEncryptionOutput`](crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct StopDeliveryStreamEncryptionOutputBuilder {
    _request_id: Option<String>,
}
impl StopDeliveryStreamEncryptionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopDeliveryStreamEncryptionOutput`](crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput).
    pub fn build(self) -> crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput {
        crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput {
            _request_id: self._request_id,
        }
    }
}