// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDeliveryStreamOutput {
    /// <p>Information about the delivery stream.</p>
    pub delivery_stream_description: ::std::option::Option<crate::types::DeliveryStreamDescription>,
    _request_id: Option<String>,
}
impl DescribeDeliveryStreamOutput {
    /// <p>Information about the delivery stream.</p>
    pub fn delivery_stream_description(&self) -> ::std::option::Option<&crate::types::DeliveryStreamDescription> {
        self.delivery_stream_description.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDeliveryStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDeliveryStreamOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDeliveryStreamOutput`](crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput).
    pub fn builder() -> crate::operation::describe_delivery_stream::builders::DescribeDeliveryStreamOutputBuilder {
        crate::operation::describe_delivery_stream::builders::DescribeDeliveryStreamOutputBuilder::default()
    }
}

/// A builder for [`DescribeDeliveryStreamOutput`](crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DescribeDeliveryStreamOutputBuilder {
    pub(crate) delivery_stream_description: ::std::option::Option<crate::types::DeliveryStreamDescription>,
    _request_id: Option<String>,
}
impl DescribeDeliveryStreamOutputBuilder {
    /// <p>Information about the delivery stream.</p>
    /// This field is required.
    pub fn delivery_stream_description(mut self, input: crate::types::DeliveryStreamDescription) -> Self {
        self.delivery_stream_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the delivery stream.</p>
    pub fn set_delivery_stream_description(mut self, input: ::std::option::Option<crate::types::DeliveryStreamDescription>) -> Self {
        self.delivery_stream_description = input;
        self
    }
    /// <p>Information about the delivery stream.</p>
    pub fn get_delivery_stream_description(&self) -> &::std::option::Option<crate::types::DeliveryStreamDescription> {
        &self.delivery_stream_description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDeliveryStreamOutput`](crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput).
    pub fn build(self) -> crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput {
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamOutput {
            delivery_stream_description: self.delivery_stream_description,
            _request_id: self._request_id,
        }
    }
}