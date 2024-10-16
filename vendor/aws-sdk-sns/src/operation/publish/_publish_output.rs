// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Response for Publish action.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PublishOutput {
    /// <p>Unique identifier assigned to the published message.</p>
    /// <p>Length Constraint: Maximum 100 characters</p>
    pub message_id: ::std::option::Option<::std::string::String>,
    /// <p>This response element applies only to FIFO (first-in-first-out) topics. </p>
    /// <p>The sequence number is a large, non-consecutive number that Amazon SNS assigns to each message. The length of <code>SequenceNumber</code> is 128 bits. <code>SequenceNumber</code> continues to increase for each <code>MessageGroupId</code>.</p>
    pub sequence_number: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PublishOutput {
    /// <p>Unique identifier assigned to the published message.</p>
    /// <p>Length Constraint: Maximum 100 characters</p>
    pub fn message_id(&self) -> ::std::option::Option<&str> {
        self.message_id.as_deref()
    }
    /// <p>This response element applies only to FIFO (first-in-first-out) topics. </p>
    /// <p>The sequence number is a large, non-consecutive number that Amazon SNS assigns to each message. The length of <code>SequenceNumber</code> is 128 bits. <code>SequenceNumber</code> continues to increase for each <code>MessageGroupId</code>.</p>
    pub fn sequence_number(&self) -> ::std::option::Option<&str> {
        self.sequence_number.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for PublishOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PublishOutput {
    /// Creates a new builder-style object to manufacture [`PublishOutput`](crate::operation::publish::PublishOutput).
    pub fn builder() -> crate::operation::publish::builders::PublishOutputBuilder {
        crate::operation::publish::builders::PublishOutputBuilder::default()
    }
}

/// A builder for [`PublishOutput`](crate::operation::publish::PublishOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PublishOutputBuilder {
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
    pub(crate) sequence_number: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PublishOutputBuilder {
    /// <p>Unique identifier assigned to the published message.</p>
    /// <p>Length Constraint: Maximum 100 characters</p>
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier assigned to the published message.</p>
    /// <p>Length Constraint: Maximum 100 characters</p>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>Unique identifier assigned to the published message.</p>
    /// <p>Length Constraint: Maximum 100 characters</p>
    pub fn get_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_id
    }
    /// <p>This response element applies only to FIFO (first-in-first-out) topics. </p>
    /// <p>The sequence number is a large, non-consecutive number that Amazon SNS assigns to each message. The length of <code>SequenceNumber</code> is 128 bits. <code>SequenceNumber</code> continues to increase for each <code>MessageGroupId</code>.</p>
    pub fn sequence_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sequence_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This response element applies only to FIFO (first-in-first-out) topics. </p>
    /// <p>The sequence number is a large, non-consecutive number that Amazon SNS assigns to each message. The length of <code>SequenceNumber</code> is 128 bits. <code>SequenceNumber</code> continues to increase for each <code>MessageGroupId</code>.</p>
    pub fn set_sequence_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sequence_number = input;
        self
    }
    /// <p>This response element applies only to FIFO (first-in-first-out) topics. </p>
    /// <p>The sequence number is a large, non-consecutive number that Amazon SNS assigns to each message. The length of <code>SequenceNumber</code> is 128 bits. <code>SequenceNumber</code> continues to increase for each <code>MessageGroupId</code>.</p>
    pub fn get_sequence_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.sequence_number
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PublishOutput`](crate::operation::publish::PublishOutput).
    pub fn build(self) -> crate::operation::publish::PublishOutput {
        crate::operation::publish::PublishOutput {
            message_id: self.message_id,
            sequence_number: self.sequence_number,
            _request_id: self._request_id,
        }
    }
}