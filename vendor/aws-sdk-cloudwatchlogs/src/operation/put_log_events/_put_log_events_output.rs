// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutLogEventsOutput {
    /// <p>The next sequence token.</p> <important>
    /// <p>This field has been deprecated.</p>
    /// <p>The sequence token is now ignored in <code>PutLogEvents</code> actions. <code>PutLogEvents</code> actions are always accepted even if the sequence token is not valid. You can use parallel <code>PutLogEvents</code> actions on the same log stream and you do not need to wait for the response of a previous <code>PutLogEvents</code> action to obtain the <code>nextSequenceToken</code> value.</p>
    /// </important>
    pub next_sequence_token: ::std::option::Option<::std::string::String>,
    /// <p>The rejected events.</p>
    pub rejected_log_events_info: ::std::option::Option<crate::types::RejectedLogEventsInfo>,
    _request_id: Option<String>,
}
impl PutLogEventsOutput {
    /// <p>The next sequence token.</p> <important>
    /// <p>This field has been deprecated.</p>
    /// <p>The sequence token is now ignored in <code>PutLogEvents</code> actions. <code>PutLogEvents</code> actions are always accepted even if the sequence token is not valid. You can use parallel <code>PutLogEvents</code> actions on the same log stream and you do not need to wait for the response of a previous <code>PutLogEvents</code> action to obtain the <code>nextSequenceToken</code> value.</p>
    /// </important>
    pub fn next_sequence_token(&self) -> ::std::option::Option<&str> {
        self.next_sequence_token.as_deref()
    }
    /// <p>The rejected events.</p>
    pub fn rejected_log_events_info(&self) -> ::std::option::Option<&crate::types::RejectedLogEventsInfo> {
        self.rejected_log_events_info.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutLogEventsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutLogEventsOutput {
    /// Creates a new builder-style object to manufacture [`PutLogEventsOutput`](crate::operation::put_log_events::PutLogEventsOutput).
    pub fn builder() -> crate::operation::put_log_events::builders::PutLogEventsOutputBuilder {
        crate::operation::put_log_events::builders::PutLogEventsOutputBuilder::default()
    }
}

/// A builder for [`PutLogEventsOutput`](crate::operation::put_log_events::PutLogEventsOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutLogEventsOutputBuilder {
    pub(crate) next_sequence_token: ::std::option::Option<::std::string::String>,
    pub(crate) rejected_log_events_info: ::std::option::Option<crate::types::RejectedLogEventsInfo>,
    _request_id: Option<String>,
}
impl PutLogEventsOutputBuilder {
    /// <p>The next sequence token.</p> <important>
    /// <p>This field has been deprecated.</p>
    /// <p>The sequence token is now ignored in <code>PutLogEvents</code> actions. <code>PutLogEvents</code> actions are always accepted even if the sequence token is not valid. You can use parallel <code>PutLogEvents</code> actions on the same log stream and you do not need to wait for the response of a previous <code>PutLogEvents</code> action to obtain the <code>nextSequenceToken</code> value.</p>
    /// </important>
    pub fn next_sequence_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_sequence_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next sequence token.</p> <important>
    /// <p>This field has been deprecated.</p>
    /// <p>The sequence token is now ignored in <code>PutLogEvents</code> actions. <code>PutLogEvents</code> actions are always accepted even if the sequence token is not valid. You can use parallel <code>PutLogEvents</code> actions on the same log stream and you do not need to wait for the response of a previous <code>PutLogEvents</code> action to obtain the <code>nextSequenceToken</code> value.</p>
    /// </important>
    pub fn set_next_sequence_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_sequence_token = input;
        self
    }
    /// <p>The next sequence token.</p> <important>
    /// <p>This field has been deprecated.</p>
    /// <p>The sequence token is now ignored in <code>PutLogEvents</code> actions. <code>PutLogEvents</code> actions are always accepted even if the sequence token is not valid. You can use parallel <code>PutLogEvents</code> actions on the same log stream and you do not need to wait for the response of a previous <code>PutLogEvents</code> action to obtain the <code>nextSequenceToken</code> value.</p>
    /// </important>
    pub fn get_next_sequence_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_sequence_token
    }
    /// <p>The rejected events.</p>
    pub fn rejected_log_events_info(mut self, input: crate::types::RejectedLogEventsInfo) -> Self {
        self.rejected_log_events_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>The rejected events.</p>
    pub fn set_rejected_log_events_info(mut self, input: ::std::option::Option<crate::types::RejectedLogEventsInfo>) -> Self {
        self.rejected_log_events_info = input;
        self
    }
    /// <p>The rejected events.</p>
    pub fn get_rejected_log_events_info(&self) -> &::std::option::Option<crate::types::RejectedLogEventsInfo> {
        &self.rejected_log_events_info
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutLogEventsOutput`](crate::operation::put_log_events::PutLogEventsOutput).
    pub fn build(self) -> crate::operation::put_log_events::PutLogEventsOutput {
        crate::operation::put_log_events::PutLogEventsOutput {
            next_sequence_token: self.next_sequence_token,
            rejected_log_events_info: self.rejected_log_events_info,
            _request_id: self._request_id,
        }
    }
}