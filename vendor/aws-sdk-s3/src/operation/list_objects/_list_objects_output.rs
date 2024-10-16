// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListObjectsOutput {
    /// <p>A flag that indicates whether Amazon S3 returned all of the results that satisfied the search criteria.</p>
    pub is_truncated: ::std::option::Option<bool>,
    /// <p>Indicates where in the bucket listing begins. Marker is included in the response if it was sent with the request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>When the response is truncated (the <code>IsTruncated</code> element value in the response is <code>true</code>), you can use the key name in this field as the <code>marker</code> parameter in the subsequent request to get the next set of objects. Amazon S3 lists objects in alphabetical order. </p> <note>
    /// <p>This element is returned only if you have the <code>delimiter</code> request parameter specified. If the response does not include the <code>NextMarker</code> element and it is truncated, you can use the value of the last <code>Key</code> element in the response as the <code>marker</code> parameter in the subsequent request to get the next set of object keys.</p>
    /// </note>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>Metadata about each object returned.</p>
    pub contents: ::std::option::Option<::std::vec::Vec<crate::types::Object>>,
    /// <p>The bucket name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Keys that begin with the indicated prefix.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>Causes keys that contain the same string between the prefix and the first occurrence of the delimiter to be rolled up into a single result element in the <code>CommonPrefixes</code> collection. These rolled-up keys are not returned elsewhere in the response. Each rolled-up result counts as only one return against the <code>MaxKeys</code> value.</p>
    pub delimiter: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of keys returned in the response body.</p>
    pub max_keys: ::std::option::Option<i32>,
    /// <p>All of the keys (up to 1,000) rolled up in a common prefix count as a single return when calculating the number of returns. </p>
    /// <p>A response can contain <code>CommonPrefixes</code> only if you specify a delimiter.</p>
    /// <p> <code>CommonPrefixes</code> contains all (if there are any) keys between <code>Prefix</code> and the next occurrence of the string specified by the delimiter.</p>
    /// <p> <code>CommonPrefixes</code> lists keys that act like subdirectories in the directory specified by <code>Prefix</code>.</p>
    /// <p>For example, if the prefix is <code>notes/</code> and the delimiter is a slash (<code>/</code>), as in <code>notes/summer/july</code>, the common prefix is <code>notes/summer/</code>. All of the keys that roll up into a common prefix count as a single return when calculating the number of returns.</p>
    pub common_prefixes: ::std::option::Option<::std::vec::Vec<crate::types::CommonPrefix>>,
    /// <p>Encoding type used by Amazon S3 to encode object keys in the response.</p>
    pub encoding_type: ::std::option::Option<crate::types::EncodingType>,
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub request_charged: ::std::option::Option<crate::types::RequestCharged>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListObjectsOutput {
    /// <p>A flag that indicates whether Amazon S3 returned all of the results that satisfied the search criteria.</p>
    pub fn is_truncated(&self) -> ::std::option::Option<bool> {
        self.is_truncated
    }
    /// <p>Indicates where in the bucket listing begins. Marker is included in the response if it was sent with the request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>When the response is truncated (the <code>IsTruncated</code> element value in the response is <code>true</code>), you can use the key name in this field as the <code>marker</code> parameter in the subsequent request to get the next set of objects. Amazon S3 lists objects in alphabetical order. </p> <note>
    /// <p>This element is returned only if you have the <code>delimiter</code> request parameter specified. If the response does not include the <code>NextMarker</code> element and it is truncated, you can use the value of the last <code>Key</code> element in the response as the <code>marker</code> parameter in the subsequent request to get the next set of object keys.</p>
    /// </note>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>Metadata about each object returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.contents.is_none()`.
    pub fn contents(&self) -> &[crate::types::Object] {
        self.contents.as_deref().unwrap_or_default()
    }
    /// <p>The bucket name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Keys that begin with the indicated prefix.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>Causes keys that contain the same string between the prefix and the first occurrence of the delimiter to be rolled up into a single result element in the <code>CommonPrefixes</code> collection. These rolled-up keys are not returned elsewhere in the response. Each rolled-up result counts as only one return against the <code>MaxKeys</code> value.</p>
    pub fn delimiter(&self) -> ::std::option::Option<&str> {
        self.delimiter.as_deref()
    }
    /// <p>The maximum number of keys returned in the response body.</p>
    pub fn max_keys(&self) -> ::std::option::Option<i32> {
        self.max_keys
    }
    /// <p>All of the keys (up to 1,000) rolled up in a common prefix count as a single return when calculating the number of returns. </p>
    /// <p>A response can contain <code>CommonPrefixes</code> only if you specify a delimiter.</p>
    /// <p> <code>CommonPrefixes</code> contains all (if there are any) keys between <code>Prefix</code> and the next occurrence of the string specified by the delimiter.</p>
    /// <p> <code>CommonPrefixes</code> lists keys that act like subdirectories in the directory specified by <code>Prefix</code>.</p>
    /// <p>For example, if the prefix is <code>notes/</code> and the delimiter is a slash (<code>/</code>), as in <code>notes/summer/july</code>, the common prefix is <code>notes/summer/</code>. All of the keys that roll up into a common prefix count as a single return when calculating the number of returns.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.common_prefixes.is_none()`.
    pub fn common_prefixes(&self) -> &[crate::types::CommonPrefix] {
        self.common_prefixes.as_deref().unwrap_or_default()
    }
    /// <p>Encoding type used by Amazon S3 to encode object keys in the response.</p>
    pub fn encoding_type(&self) -> ::std::option::Option<&crate::types::EncodingType> {
        self.encoding_type.as_ref()
    }
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_charged(&self) -> ::std::option::Option<&crate::types::RequestCharged> {
        self.request_charged.as_ref()
    }
}
impl crate::s3_request_id::RequestIdExt for ListObjectsOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListObjectsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListObjectsOutput {
    /// Creates a new builder-style object to manufacture [`ListObjectsOutput`](crate::operation::list_objects::ListObjectsOutput).
    pub fn builder() -> crate::operation::list_objects::builders::ListObjectsOutputBuilder {
        crate::operation::list_objects::builders::ListObjectsOutputBuilder::default()
    }
}

/// A builder for [`ListObjectsOutput`](crate::operation::list_objects::ListObjectsOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ListObjectsOutputBuilder {
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) contents: ::std::option::Option<::std::vec::Vec<crate::types::Object>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) delimiter: ::std::option::Option<::std::string::String>,
    pub(crate) max_keys: ::std::option::Option<i32>,
    pub(crate) common_prefixes: ::std::option::Option<::std::vec::Vec<crate::types::CommonPrefix>>,
    pub(crate) encoding_type: ::std::option::Option<crate::types::EncodingType>,
    pub(crate) request_charged: ::std::option::Option<crate::types::RequestCharged>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListObjectsOutputBuilder {
    /// <p>A flag that indicates whether Amazon S3 returned all of the results that satisfied the search criteria.</p>
    pub fn is_truncated(mut self, input: bool) -> Self {
        self.is_truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that indicates whether Amazon S3 returned all of the results that satisfied the search criteria.</p>
    pub fn set_is_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_truncated = input;
        self
    }
    /// <p>A flag that indicates whether Amazon S3 returned all of the results that satisfied the search criteria.</p>
    pub fn get_is_truncated(&self) -> &::std::option::Option<bool> {
        &self.is_truncated
    }
    /// <p>Indicates where in the bucket listing begins. Marker is included in the response if it was sent with the request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates where in the bucket listing begins. Marker is included in the response if it was sent with the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Indicates where in the bucket listing begins. Marker is included in the response if it was sent with the request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>When the response is truncated (the <code>IsTruncated</code> element value in the response is <code>true</code>), you can use the key name in this field as the <code>marker</code> parameter in the subsequent request to get the next set of objects. Amazon S3 lists objects in alphabetical order. </p> <note>
    /// <p>This element is returned only if you have the <code>delimiter</code> request parameter specified. If the response does not include the <code>NextMarker</code> element and it is truncated, you can use the value of the last <code>Key</code> element in the response as the <code>marker</code> parameter in the subsequent request to get the next set of object keys.</p>
    /// </note>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the response is truncated (the <code>IsTruncated</code> element value in the response is <code>true</code>), you can use the key name in this field as the <code>marker</code> parameter in the subsequent request to get the next set of objects. Amazon S3 lists objects in alphabetical order. </p> <note>
    /// <p>This element is returned only if you have the <code>delimiter</code> request parameter specified. If the response does not include the <code>NextMarker</code> element and it is truncated, you can use the value of the last <code>Key</code> element in the response as the <code>marker</code> parameter in the subsequent request to get the next set of object keys.</p>
    /// </note>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>When the response is truncated (the <code>IsTruncated</code> element value in the response is <code>true</code>), you can use the key name in this field as the <code>marker</code> parameter in the subsequent request to get the next set of objects. Amazon S3 lists objects in alphabetical order. </p> <note>
    /// <p>This element is returned only if you have the <code>delimiter</code> request parameter specified. If the response does not include the <code>NextMarker</code> element and it is truncated, you can use the value of the last <code>Key</code> element in the response as the <code>marker</code> parameter in the subsequent request to get the next set of object keys.</p>
    /// </note>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// Appends an item to `contents`.
    ///
    /// To override the contents of this collection use [`set_contents`](Self::set_contents).
    ///
    /// <p>Metadata about each object returned.</p>
    pub fn contents(mut self, input: crate::types::Object) -> Self {
        let mut v = self.contents.unwrap_or_default();
        v.push(input);
        self.contents = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata about each object returned.</p>
    pub fn set_contents(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Object>>) -> Self {
        self.contents = input;
        self
    }
    /// <p>Metadata about each object returned.</p>
    pub fn get_contents(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Object>> {
        &self.contents
    }
    /// <p>The bucket name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bucket name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The bucket name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Keys that begin with the indicated prefix.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Keys that begin with the indicated prefix.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>Keys that begin with the indicated prefix.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p>Causes keys that contain the same string between the prefix and the first occurrence of the delimiter to be rolled up into a single result element in the <code>CommonPrefixes</code> collection. These rolled-up keys are not returned elsewhere in the response. Each rolled-up result counts as only one return against the <code>MaxKeys</code> value.</p>
    pub fn delimiter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delimiter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Causes keys that contain the same string between the prefix and the first occurrence of the delimiter to be rolled up into a single result element in the <code>CommonPrefixes</code> collection. These rolled-up keys are not returned elsewhere in the response. Each rolled-up result counts as only one return against the <code>MaxKeys</code> value.</p>
    pub fn set_delimiter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delimiter = input;
        self
    }
    /// <p>Causes keys that contain the same string between the prefix and the first occurrence of the delimiter to be rolled up into a single result element in the <code>CommonPrefixes</code> collection. These rolled-up keys are not returned elsewhere in the response. Each rolled-up result counts as only one return against the <code>MaxKeys</code> value.</p>
    pub fn get_delimiter(&self) -> &::std::option::Option<::std::string::String> {
        &self.delimiter
    }
    /// <p>The maximum number of keys returned in the response body.</p>
    pub fn max_keys(mut self, input: i32) -> Self {
        self.max_keys = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of keys returned in the response body.</p>
    pub fn set_max_keys(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_keys = input;
        self
    }
    /// <p>The maximum number of keys returned in the response body.</p>
    pub fn get_max_keys(&self) -> &::std::option::Option<i32> {
        &self.max_keys
    }
    /// Appends an item to `common_prefixes`.
    ///
    /// To override the contents of this collection use [`set_common_prefixes`](Self::set_common_prefixes).
    ///
    /// <p>All of the keys (up to 1,000) rolled up in a common prefix count as a single return when calculating the number of returns. </p>
    /// <p>A response can contain <code>CommonPrefixes</code> only if you specify a delimiter.</p>
    /// <p> <code>CommonPrefixes</code> contains all (if there are any) keys between <code>Prefix</code> and the next occurrence of the string specified by the delimiter.</p>
    /// <p> <code>CommonPrefixes</code> lists keys that act like subdirectories in the directory specified by <code>Prefix</code>.</p>
    /// <p>For example, if the prefix is <code>notes/</code> and the delimiter is a slash (<code>/</code>), as in <code>notes/summer/july</code>, the common prefix is <code>notes/summer/</code>. All of the keys that roll up into a common prefix count as a single return when calculating the number of returns.</p>
    pub fn common_prefixes(mut self, input: crate::types::CommonPrefix) -> Self {
        let mut v = self.common_prefixes.unwrap_or_default();
        v.push(input);
        self.common_prefixes = ::std::option::Option::Some(v);
        self
    }
    /// <p>All of the keys (up to 1,000) rolled up in a common prefix count as a single return when calculating the number of returns. </p>
    /// <p>A response can contain <code>CommonPrefixes</code> only if you specify a delimiter.</p>
    /// <p> <code>CommonPrefixes</code> contains all (if there are any) keys between <code>Prefix</code> and the next occurrence of the string specified by the delimiter.</p>
    /// <p> <code>CommonPrefixes</code> lists keys that act like subdirectories in the directory specified by <code>Prefix</code>.</p>
    /// <p>For example, if the prefix is <code>notes/</code> and the delimiter is a slash (<code>/</code>), as in <code>notes/summer/july</code>, the common prefix is <code>notes/summer/</code>. All of the keys that roll up into a common prefix count as a single return when calculating the number of returns.</p>
    pub fn set_common_prefixes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CommonPrefix>>) -> Self {
        self.common_prefixes = input;
        self
    }
    /// <p>All of the keys (up to 1,000) rolled up in a common prefix count as a single return when calculating the number of returns. </p>
    /// <p>A response can contain <code>CommonPrefixes</code> only if you specify a delimiter.</p>
    /// <p> <code>CommonPrefixes</code> contains all (if there are any) keys between <code>Prefix</code> and the next occurrence of the string specified by the delimiter.</p>
    /// <p> <code>CommonPrefixes</code> lists keys that act like subdirectories in the directory specified by <code>Prefix</code>.</p>
    /// <p>For example, if the prefix is <code>notes/</code> and the delimiter is a slash (<code>/</code>), as in <code>notes/summer/july</code>, the common prefix is <code>notes/summer/</code>. All of the keys that roll up into a common prefix count as a single return when calculating the number of returns.</p>
    pub fn get_common_prefixes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CommonPrefix>> {
        &self.common_prefixes
    }
    /// <p>Encoding type used by Amazon S3 to encode object keys in the response.</p>
    pub fn encoding_type(mut self, input: crate::types::EncodingType) -> Self {
        self.encoding_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Encoding type used by Amazon S3 to encode object keys in the response.</p>
    pub fn set_encoding_type(mut self, input: ::std::option::Option<crate::types::EncodingType>) -> Self {
        self.encoding_type = input;
        self
    }
    /// <p>Encoding type used by Amazon S3 to encode object keys in the response.</p>
    pub fn get_encoding_type(&self) -> &::std::option::Option<crate::types::EncodingType> {
        &self.encoding_type
    }
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_charged(mut self, input: crate::types::RequestCharged) -> Self {
        self.request_charged = ::std::option::Option::Some(input);
        self
    }
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn set_request_charged(mut self, input: ::std::option::Option<crate::types::RequestCharged>) -> Self {
        self.request_charged = input;
        self
    }
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn get_request_charged(&self) -> &::std::option::Option<crate::types::RequestCharged> {
        &self.request_charged
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
    /// Consumes the builder and constructs a [`ListObjectsOutput`](crate::operation::list_objects::ListObjectsOutput).
    pub fn build(self) -> crate::operation::list_objects::ListObjectsOutput {
        crate::operation::list_objects::ListObjectsOutput {
            is_truncated: self.is_truncated,
            marker: self.marker,
            next_marker: self.next_marker,
            contents: self.contents,
            name: self.name,
            prefix: self.prefix,
            delimiter: self.delimiter,
            max_keys: self.max_keys,
            common_prefixes: self.common_prefixes,
            encoding_type: self.encoding_type,
            request_charged: self.request_charged,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}