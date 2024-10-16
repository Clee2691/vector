// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListObjectVersionsInput {
    /// <p>The bucket name that contains the objects. </p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>A delimiter is a character that you specify to group keys. All keys that contain the same string between the <code>prefix</code> and the first occurrence of the delimiter are grouped under a single result element in <code>CommonPrefixes</code>. These groups are counted as one result against the <code>max-keys</code> limitation. These keys are not returned elsewhere in the response.</p>
    pub delimiter: ::std::option::Option<::std::string::String>,
    /// <p>Requests Amazon S3 to encode the object keys in the response and specifies the encoding method to use. An object key can contain any Unicode character; however, the XML 1.0 parser cannot parse some characters, such as characters with an ASCII value from 0 to 10. For characters that are not supported in XML 1.0, you can add this parameter to request that Amazon S3 encode the keys in the response.</p>
    pub encoding_type: ::std::option::Option<crate::types::EncodingType>,
    /// <p>Specifies the key to start with when listing objects in a bucket.</p>
    pub key_marker: ::std::option::Option<::std::string::String>,
    /// <p>Sets the maximum number of keys returned in the response. By default, the action returns up to 1,000 key names. The response might contain fewer keys but will never contain more. If additional keys satisfy the search criteria, but were not returned because <code>max-keys</code> was exceeded, the response contains <code>
    /// <istruncated>
    /// true
    /// </istruncated></code>. To return the additional keys, see <code>key-marker</code> and <code>version-id-marker</code>.</p>
    pub max_keys: ::std::option::Option<i32>,
    /// <p>Use this parameter to select only those keys that begin with the specified prefix. You can use prefixes to separate a bucket into different groupings of keys. (You can think of using <code>prefix</code> to make groups in the same way that you'd use a folder in a file system.) You can use <code>prefix</code> with <code>delimiter</code> to roll up numerous objects into a single result under <code>CommonPrefixes</code>. </p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the object version you want to start listing from.</p>
    pub version_id_marker: ::std::option::Option<::std::string::String>,
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
    /// <p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub request_payer: ::std::option::Option<crate::types::RequestPayer>,
    /// <p>Specifies the optional fields that you want returned in the response. Fields that you do not specify are not returned.</p>
    pub optional_object_attributes: ::std::option::Option<::std::vec::Vec<crate::types::OptionalObjectAttributes>>,
}
impl ListObjectVersionsInput {
    /// <p>The bucket name that contains the objects. </p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>A delimiter is a character that you specify to group keys. All keys that contain the same string between the <code>prefix</code> and the first occurrence of the delimiter are grouped under a single result element in <code>CommonPrefixes</code>. These groups are counted as one result against the <code>max-keys</code> limitation. These keys are not returned elsewhere in the response.</p>
    pub fn delimiter(&self) -> ::std::option::Option<&str> {
        self.delimiter.as_deref()
    }
    /// <p>Requests Amazon S3 to encode the object keys in the response and specifies the encoding method to use. An object key can contain any Unicode character; however, the XML 1.0 parser cannot parse some characters, such as characters with an ASCII value from 0 to 10. For characters that are not supported in XML 1.0, you can add this parameter to request that Amazon S3 encode the keys in the response.</p>
    pub fn encoding_type(&self) -> ::std::option::Option<&crate::types::EncodingType> {
        self.encoding_type.as_ref()
    }
    /// <p>Specifies the key to start with when listing objects in a bucket.</p>
    pub fn key_marker(&self) -> ::std::option::Option<&str> {
        self.key_marker.as_deref()
    }
    /// <p>Sets the maximum number of keys returned in the response. By default, the action returns up to 1,000 key names. The response might contain fewer keys but will never contain more. If additional keys satisfy the search criteria, but were not returned because <code>max-keys</code> was exceeded, the response contains <code>
    /// <istruncated>
    /// true
    /// </istruncated></code>. To return the additional keys, see <code>key-marker</code> and <code>version-id-marker</code>.</p>
    pub fn max_keys(&self) -> ::std::option::Option<i32> {
        self.max_keys
    }
    /// <p>Use this parameter to select only those keys that begin with the specified prefix. You can use prefixes to separate a bucket into different groupings of keys. (You can think of using <code>prefix</code> to make groups in the same way that you'd use a folder in a file system.) You can use <code>prefix</code> with <code>delimiter</code> to roll up numerous objects into a single result under <code>CommonPrefixes</code>. </p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>Specifies the object version you want to start listing from.</p>
    pub fn version_id_marker(&self) -> ::std::option::Option<&str> {
        self.version_id_marker.as_deref()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
    /// <p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_payer(&self) -> ::std::option::Option<&crate::types::RequestPayer> {
        self.request_payer.as_ref()
    }
    /// <p>Specifies the optional fields that you want returned in the response. Fields that you do not specify are not returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.optional_object_attributes.is_none()`.
    pub fn optional_object_attributes(&self) -> &[crate::types::OptionalObjectAttributes] {
        self.optional_object_attributes.as_deref().unwrap_or_default()
    }
}
impl ListObjectVersionsInput {
    /// Creates a new builder-style object to manufacture [`ListObjectVersionsInput`](crate::operation::list_object_versions::ListObjectVersionsInput).
    pub fn builder() -> crate::operation::list_object_versions::builders::ListObjectVersionsInputBuilder {
        crate::operation::list_object_versions::builders::ListObjectVersionsInputBuilder::default()
    }
}

/// A builder for [`ListObjectVersionsInput`](crate::operation::list_object_versions::ListObjectVersionsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ListObjectVersionsInputBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) delimiter: ::std::option::Option<::std::string::String>,
    pub(crate) encoding_type: ::std::option::Option<crate::types::EncodingType>,
    pub(crate) key_marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_keys: ::std::option::Option<i32>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) version_id_marker: ::std::option::Option<::std::string::String>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
    pub(crate) request_payer: ::std::option::Option<crate::types::RequestPayer>,
    pub(crate) optional_object_attributes: ::std::option::Option<::std::vec::Vec<crate::types::OptionalObjectAttributes>>,
}
impl ListObjectVersionsInputBuilder {
    /// <p>The bucket name that contains the objects. </p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bucket name that contains the objects. </p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The bucket name that contains the objects. </p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>A delimiter is a character that you specify to group keys. All keys that contain the same string between the <code>prefix</code> and the first occurrence of the delimiter are grouped under a single result element in <code>CommonPrefixes</code>. These groups are counted as one result against the <code>max-keys</code> limitation. These keys are not returned elsewhere in the response.</p>
    pub fn delimiter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delimiter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A delimiter is a character that you specify to group keys. All keys that contain the same string between the <code>prefix</code> and the first occurrence of the delimiter are grouped under a single result element in <code>CommonPrefixes</code>. These groups are counted as one result against the <code>max-keys</code> limitation. These keys are not returned elsewhere in the response.</p>
    pub fn set_delimiter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delimiter = input;
        self
    }
    /// <p>A delimiter is a character that you specify to group keys. All keys that contain the same string between the <code>prefix</code> and the first occurrence of the delimiter are grouped under a single result element in <code>CommonPrefixes</code>. These groups are counted as one result against the <code>max-keys</code> limitation. These keys are not returned elsewhere in the response.</p>
    pub fn get_delimiter(&self) -> &::std::option::Option<::std::string::String> {
        &self.delimiter
    }
    /// <p>Requests Amazon S3 to encode the object keys in the response and specifies the encoding method to use. An object key can contain any Unicode character; however, the XML 1.0 parser cannot parse some characters, such as characters with an ASCII value from 0 to 10. For characters that are not supported in XML 1.0, you can add this parameter to request that Amazon S3 encode the keys in the response.</p>
    pub fn encoding_type(mut self, input: crate::types::EncodingType) -> Self {
        self.encoding_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Requests Amazon S3 to encode the object keys in the response and specifies the encoding method to use. An object key can contain any Unicode character; however, the XML 1.0 parser cannot parse some characters, such as characters with an ASCII value from 0 to 10. For characters that are not supported in XML 1.0, you can add this parameter to request that Amazon S3 encode the keys in the response.</p>
    pub fn set_encoding_type(mut self, input: ::std::option::Option<crate::types::EncodingType>) -> Self {
        self.encoding_type = input;
        self
    }
    /// <p>Requests Amazon S3 to encode the object keys in the response and specifies the encoding method to use. An object key can contain any Unicode character; however, the XML 1.0 parser cannot parse some characters, such as characters with an ASCII value from 0 to 10. For characters that are not supported in XML 1.0, you can add this parameter to request that Amazon S3 encode the keys in the response.</p>
    pub fn get_encoding_type(&self) -> &::std::option::Option<crate::types::EncodingType> {
        &self.encoding_type
    }
    /// <p>Specifies the key to start with when listing objects in a bucket.</p>
    pub fn key_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the key to start with when listing objects in a bucket.</p>
    pub fn set_key_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_marker = input;
        self
    }
    /// <p>Specifies the key to start with when listing objects in a bucket.</p>
    pub fn get_key_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_marker
    }
    /// <p>Sets the maximum number of keys returned in the response. By default, the action returns up to 1,000 key names. The response might contain fewer keys but will never contain more. If additional keys satisfy the search criteria, but were not returned because <code>max-keys</code> was exceeded, the response contains <code>
    /// <istruncated>
    /// true
    /// </istruncated></code>. To return the additional keys, see <code>key-marker</code> and <code>version-id-marker</code>.</p>
    pub fn max_keys(mut self, input: i32) -> Self {
        self.max_keys = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets the maximum number of keys returned in the response. By default, the action returns up to 1,000 key names. The response might contain fewer keys but will never contain more. If additional keys satisfy the search criteria, but were not returned because <code>max-keys</code> was exceeded, the response contains <code>
    /// <istruncated>
    /// true
    /// </istruncated></code>. To return the additional keys, see <code>key-marker</code> and <code>version-id-marker</code>.</p>
    pub fn set_max_keys(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_keys = input;
        self
    }
    /// <p>Sets the maximum number of keys returned in the response. By default, the action returns up to 1,000 key names. The response might contain fewer keys but will never contain more. If additional keys satisfy the search criteria, but were not returned because <code>max-keys</code> was exceeded, the response contains <code>
    /// <istruncated>
    /// true
    /// </istruncated></code>. To return the additional keys, see <code>key-marker</code> and <code>version-id-marker</code>.</p>
    pub fn get_max_keys(&self) -> &::std::option::Option<i32> {
        &self.max_keys
    }
    /// <p>Use this parameter to select only those keys that begin with the specified prefix. You can use prefixes to separate a bucket into different groupings of keys. (You can think of using <code>prefix</code> to make groups in the same way that you'd use a folder in a file system.) You can use <code>prefix</code> with <code>delimiter</code> to roll up numerous objects into a single result under <code>CommonPrefixes</code>. </p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use this parameter to select only those keys that begin with the specified prefix. You can use prefixes to separate a bucket into different groupings of keys. (You can think of using <code>prefix</code> to make groups in the same way that you'd use a folder in a file system.) You can use <code>prefix</code> with <code>delimiter</code> to roll up numerous objects into a single result under <code>CommonPrefixes</code>. </p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>Use this parameter to select only those keys that begin with the specified prefix. You can use prefixes to separate a bucket into different groupings of keys. (You can think of using <code>prefix</code> to make groups in the same way that you'd use a folder in a file system.) You can use <code>prefix</code> with <code>delimiter</code> to roll up numerous objects into a single result under <code>CommonPrefixes</code>. </p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p>Specifies the object version you want to start listing from.</p>
    pub fn version_id_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the object version you want to start listing from.</p>
    pub fn set_version_id_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id_marker = input;
        self
    }
    /// <p>Specifies the object version you want to start listing from.</p>
    pub fn get_version_id_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id_marker
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_bucket_owner = input;
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_bucket_owner
    }
    /// <p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_payer(mut self, input: crate::types::RequestPayer) -> Self {
        self.request_payer = ::std::option::Option::Some(input);
        self
    }
    /// <p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn set_request_payer(mut self, input: ::std::option::Option<crate::types::RequestPayer>) -> Self {
        self.request_payer = input;
        self
    }
    /// <p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn get_request_payer(&self) -> &::std::option::Option<crate::types::RequestPayer> {
        &self.request_payer
    }
    /// Appends an item to `optional_object_attributes`.
    ///
    /// To override the contents of this collection use [`set_optional_object_attributes`](Self::set_optional_object_attributes).
    ///
    /// <p>Specifies the optional fields that you want returned in the response. Fields that you do not specify are not returned.</p>
    pub fn optional_object_attributes(mut self, input: crate::types::OptionalObjectAttributes) -> Self {
        let mut v = self.optional_object_attributes.unwrap_or_default();
        v.push(input);
        self.optional_object_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the optional fields that you want returned in the response. Fields that you do not specify are not returned.</p>
    pub fn set_optional_object_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OptionalObjectAttributes>>) -> Self {
        self.optional_object_attributes = input;
        self
    }
    /// <p>Specifies the optional fields that you want returned in the response. Fields that you do not specify are not returned.</p>
    pub fn get_optional_object_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OptionalObjectAttributes>> {
        &self.optional_object_attributes
    }
    /// Consumes the builder and constructs a [`ListObjectVersionsInput`](crate::operation::list_object_versions::ListObjectVersionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_object_versions::ListObjectVersionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_object_versions::ListObjectVersionsInput {
            bucket: self.bucket,
            delimiter: self.delimiter,
            encoding_type: self.encoding_type,
            key_marker: self.key_marker,
            max_keys: self.max_keys,
            prefix: self.prefix,
            version_id_marker: self.version_id_marker,
            expected_bucket_owner: self.expected_bucket_owner,
            request_payer: self.request_payer,
            optional_object_attributes: self.optional_object_attributes,
        })
    }
}