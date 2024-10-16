// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of received messages.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReceiveMessageOutput {
    /// <p>A list of messages.</p>
    pub messages: ::std::option::Option<::std::vec::Vec<crate::types::Message>>,
    _request_id: Option<String>,
}
impl ReceiveMessageOutput {
    /// <p>A list of messages.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.messages.is_none()`.
    pub fn messages(&self) -> &[crate::types::Message] {
        self.messages.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ReceiveMessageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReceiveMessageOutput {
    /// Creates a new builder-style object to manufacture [`ReceiveMessageOutput`](crate::operation::receive_message::ReceiveMessageOutput).
    pub fn builder() -> crate::operation::receive_message::builders::ReceiveMessageOutputBuilder {
        crate::operation::receive_message::builders::ReceiveMessageOutputBuilder::default()
    }
}

/// A builder for [`ReceiveMessageOutput`](crate::operation::receive_message::ReceiveMessageOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ReceiveMessageOutputBuilder {
    pub(crate) messages: ::std::option::Option<::std::vec::Vec<crate::types::Message>>,
    _request_id: Option<String>,
}
impl ReceiveMessageOutputBuilder {
    /// Appends an item to `messages`.
    ///
    /// To override the contents of this collection use [`set_messages`](Self::set_messages).
    ///
    /// <p>A list of messages.</p>
    pub fn messages(mut self, input: crate::types::Message) -> Self {
        let mut v = self.messages.unwrap_or_default();
        v.push(input);
        self.messages = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of messages.</p>
    pub fn set_messages(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Message>>) -> Self {
        self.messages = input;
        self
    }
    /// <p>A list of messages.</p>
    pub fn get_messages(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Message>> {
        &self.messages
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReceiveMessageOutput`](crate::operation::receive_message::ReceiveMessageOutput).
    pub fn build(self) -> crate::operation::receive_message::ReceiveMessageOutput {
        crate::operation::receive_message::ReceiveMessageOutput {
            messages: self.messages,
            _request_id: self._request_id,
        }
    }
}