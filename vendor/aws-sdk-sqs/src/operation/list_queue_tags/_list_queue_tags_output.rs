// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListQueueTagsOutput {
    /// <p>The list of all tags added to the specified queue.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl ListQueueTagsOutput {
    /// <p>The list of all tags added to the specified queue.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ListQueueTagsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListQueueTagsOutput {
    /// Creates a new builder-style object to manufacture [`ListQueueTagsOutput`](crate::operation::list_queue_tags::ListQueueTagsOutput).
    pub fn builder() -> crate::operation::list_queue_tags::builders::ListQueueTagsOutputBuilder {
        crate::operation::list_queue_tags::builders::ListQueueTagsOutputBuilder::default()
    }
}

/// A builder for [`ListQueueTagsOutput`](crate::operation::list_queue_tags::ListQueueTagsOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ListQueueTagsOutputBuilder {
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl ListQueueTagsOutputBuilder {
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of all tags added to the specified queue.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The list of all tags added to the specified queue.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of all tags added to the specified queue.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListQueueTagsOutput`](crate::operation::list_queue_tags::ListQueueTagsOutput).
    pub fn build(self) -> crate::operation::list_queue_tags::ListQueueTagsOutput {
        crate::operation::list_queue_tags::ListQueueTagsOutput {
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}