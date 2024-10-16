// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDirectoryBucketsOutput {
    /// <p>The list of buckets owned by the requester. </p>
    pub buckets: ::std::option::Option<::std::vec::Vec<crate::types::Bucket>>,
    /// <p>If <code>ContinuationToken</code> was sent with the request, it is included in the response. You can use the returned <code>ContinuationToken</code> for pagination of the list response.</p>
    pub continuation_token: ::std::option::Option<::std::string::String>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListDirectoryBucketsOutput {
    /// <p>The list of buckets owned by the requester. </p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.buckets.is_none()`.
    pub fn buckets(&self) -> &[crate::types::Bucket] {
        self.buckets.as_deref().unwrap_or_default()
    }
    /// <p>If <code>ContinuationToken</code> was sent with the request, it is included in the response. You can use the returned <code>ContinuationToken</code> for pagination of the list response.</p>
    pub fn continuation_token(&self) -> ::std::option::Option<&str> {
        self.continuation_token.as_deref()
    }
}
impl crate::s3_request_id::RequestIdExt for ListDirectoryBucketsOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDirectoryBucketsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDirectoryBucketsOutput {
    /// Creates a new builder-style object to manufacture [`ListDirectoryBucketsOutput`](crate::operation::list_directory_buckets::ListDirectoryBucketsOutput).
    pub fn builder() -> crate::operation::list_directory_buckets::builders::ListDirectoryBucketsOutputBuilder {
        crate::operation::list_directory_buckets::builders::ListDirectoryBucketsOutputBuilder::default()
    }
}

/// A builder for [`ListDirectoryBucketsOutput`](crate::operation::list_directory_buckets::ListDirectoryBucketsOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ListDirectoryBucketsOutputBuilder {
    pub(crate) buckets: ::std::option::Option<::std::vec::Vec<crate::types::Bucket>>,
    pub(crate) continuation_token: ::std::option::Option<::std::string::String>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListDirectoryBucketsOutputBuilder {
    /// Appends an item to `buckets`.
    ///
    /// To override the contents of this collection use [`set_buckets`](Self::set_buckets).
    ///
    /// <p>The list of buckets owned by the requester. </p>
    pub fn buckets(mut self, input: crate::types::Bucket) -> Self {
        let mut v = self.buckets.unwrap_or_default();
        v.push(input);
        self.buckets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of buckets owned by the requester. </p>
    pub fn set_buckets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Bucket>>) -> Self {
        self.buckets = input;
        self
    }
    /// <p>The list of buckets owned by the requester. </p>
    pub fn get_buckets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Bucket>> {
        &self.buckets
    }
    /// <p>If <code>ContinuationToken</code> was sent with the request, it is included in the response. You can use the returned <code>ContinuationToken</code> for pagination of the list response.</p>
    pub fn continuation_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continuation_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If <code>ContinuationToken</code> was sent with the request, it is included in the response. You can use the returned <code>ContinuationToken</code> for pagination of the list response.</p>
    pub fn set_continuation_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continuation_token = input;
        self
    }
    /// <p>If <code>ContinuationToken</code> was sent with the request, it is included in the response. You can use the returned <code>ContinuationToken</code> for pagination of the list response.</p>
    pub fn get_continuation_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.continuation_token
    }
    pub(crate) fn _extended_request_id(mut self, extended_request_id: impl Into<String>) -> Self {
        self._extended_request_id = Some(extended_request_id.into());
        self
    }

    pub(crate) fn _set_extended_request_id(&mut self, extended_request_id: Option<String>) -> &mut Self {
        self._extended_request_id = extended_request_id;
        self
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDirectoryBucketsOutput`](crate::operation::list_directory_buckets::ListDirectoryBucketsOutput).
    pub fn build(self) -> crate::operation::list_directory_buckets::ListDirectoryBucketsOutput {
        crate::operation::list_directory_buckets::ListDirectoryBucketsOutput {
            buckets: self.buckets,
            continuation_token: self.continuation_token,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}