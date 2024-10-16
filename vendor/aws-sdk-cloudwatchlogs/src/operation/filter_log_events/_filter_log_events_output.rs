// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterLogEventsOutput {
    /// <p>The matched events.</p>
    pub events: ::std::option::Option<::std::vec::Vec<crate::types::FilteredLogEvent>>,
    /// <p> <b>Important</b> As of May 15, 2020, this parameter is no longer supported. This parameter returns an empty list.</p>
    /// <p>Indicates which log streams have been searched and whether each has been searched completely.</p>
    pub searched_log_streams: ::std::option::Option<::std::vec::Vec<crate::types::SearchedLogStream>>,
    /// <p>The token to use when requesting the next set of items. The token expires after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl FilterLogEventsOutput {
    /// <p>The matched events.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.events.is_none()`.
    pub fn events(&self) -> &[crate::types::FilteredLogEvent] {
        self.events.as_deref().unwrap_or_default()
    }
    /// <p> <b>Important</b> As of May 15, 2020, this parameter is no longer supported. This parameter returns an empty list.</p>
    /// <p>Indicates which log streams have been searched and whether each has been searched completely.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.searched_log_streams.is_none()`.
    pub fn searched_log_streams(&self) -> &[crate::types::SearchedLogStream] {
        self.searched_log_streams.as_deref().unwrap_or_default()
    }
    /// <p>The token to use when requesting the next set of items. The token expires after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for FilterLogEventsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl FilterLogEventsOutput {
    /// Creates a new builder-style object to manufacture [`FilterLogEventsOutput`](crate::operation::filter_log_events::FilterLogEventsOutput).
    pub fn builder() -> crate::operation::filter_log_events::builders::FilterLogEventsOutputBuilder {
        crate::operation::filter_log_events::builders::FilterLogEventsOutputBuilder::default()
    }
}

/// A builder for [`FilterLogEventsOutput`](crate::operation::filter_log_events::FilterLogEventsOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct FilterLogEventsOutputBuilder {
    pub(crate) events: ::std::option::Option<::std::vec::Vec<crate::types::FilteredLogEvent>>,
    pub(crate) searched_log_streams: ::std::option::Option<::std::vec::Vec<crate::types::SearchedLogStream>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl FilterLogEventsOutputBuilder {
    /// Appends an item to `events`.
    ///
    /// To override the contents of this collection use [`set_events`](Self::set_events).
    ///
    /// <p>The matched events.</p>
    pub fn events(mut self, input: crate::types::FilteredLogEvent) -> Self {
        let mut v = self.events.unwrap_or_default();
        v.push(input);
        self.events = ::std::option::Option::Some(v);
        self
    }
    /// <p>The matched events.</p>
    pub fn set_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilteredLogEvent>>) -> Self {
        self.events = input;
        self
    }
    /// <p>The matched events.</p>
    pub fn get_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilteredLogEvent>> {
        &self.events
    }
    /// Appends an item to `searched_log_streams`.
    ///
    /// To override the contents of this collection use [`set_searched_log_streams`](Self::set_searched_log_streams).
    ///
    /// <p> <b>Important</b> As of May 15, 2020, this parameter is no longer supported. This parameter returns an empty list.</p>
    /// <p>Indicates which log streams have been searched and whether each has been searched completely.</p>
    pub fn searched_log_streams(mut self, input: crate::types::SearchedLogStream) -> Self {
        let mut v = self.searched_log_streams.unwrap_or_default();
        v.push(input);
        self.searched_log_streams = ::std::option::Option::Some(v);
        self
    }
    /// <p> <b>Important</b> As of May 15, 2020, this parameter is no longer supported. This parameter returns an empty list.</p>
    /// <p>Indicates which log streams have been searched and whether each has been searched completely.</p>
    pub fn set_searched_log_streams(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SearchedLogStream>>) -> Self {
        self.searched_log_streams = input;
        self
    }
    /// <p> <b>Important</b> As of May 15, 2020, this parameter is no longer supported. This parameter returns an empty list.</p>
    /// <p>Indicates which log streams have been searched and whether each has been searched completely.</p>
    pub fn get_searched_log_streams(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SearchedLogStream>> {
        &self.searched_log_streams
    }
    /// <p>The token to use when requesting the next set of items. The token expires after 24 hours.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use when requesting the next set of items. The token expires after 24 hours.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use when requesting the next set of items. The token expires after 24 hours.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`FilterLogEventsOutput`](crate::operation::filter_log_events::FilterLogEventsOutput).
    pub fn build(self) -> crate::operation::filter_log_events::FilterLogEventsOutput {
        crate::operation::filter_log_events::FilterLogEventsOutput {
            events: self.events,
            searched_log_streams: self.searched_log_streams,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}