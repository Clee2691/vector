// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListObjects`](crate::operation::list_objects::builders::ListObjectsFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket containing the objects.</p>  <p> <b>Directory buckets</b> - When you use this operation with a directory bucket, you must use virtual-hosted-style requests in the format <code> <i>Bucket_name</i>.s3express-<i>az_id</i>.<i>region</i>.amazonaws.com</code>. Path-style requests are not supported. Directory bucket names must be unique in the chosen Availability Zone. Bucket names must follow the format <code> <i>bucket_base_name</i>--<i>az-id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az2</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i>.</p>  <p> <b>Access points</b> - When you use this action with an access point, you must provide the alias of the access point in place of the bucket name or specify the access point ARN. When using the access point ARN, you must direct requests to the access point hostname. The access point hostname takes the form <i>AccessPointName</i>-<i>AccountId</i>.s3-accesspoint.<i>Region</i>.amazonaws.com. When using this action with an access point through the Amazon Web Services SDKs, you provide the access point ARN in place of the bucket name. For more information about access point ARNs, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-access-points.html">Using access points</a> in the <i>Amazon S3 User Guide</i>.</p> <note>   <p>Access points and Object Lambda access points are not supported by directory buckets.</p>  </note>  <p> <b>S3 on Outposts</b> - When you use this action with Amazon S3 on Outposts, you must direct requests to the S3 on Outposts hostname. The S3 on Outposts hostname takes the form <code> <i>AccessPointName</i>-<i>AccountId</i>.<i>outpostID</i>.s3-outposts.<i>Region</i>.amazonaws.com</code>. When you use this action with S3 on Outposts through the Amazon Web Services SDKs, you provide the Outposts access point ARN in place of the bucket name. For more information about S3 on Outposts ARNs, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/S3onOutposts.html">What is S3 on Outposts?</a> in the <i>Amazon S3 User Guide</i>.</p><br>
    ///   - [`delimiter(impl Into<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::delimiter) / [`set_delimiter(Option<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_delimiter):<br>required: **false**<br><p>A delimiter is a character that you use to group keys.</p><br>
    ///   - [`encoding_type(EncodingType)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::encoding_type) / [`set_encoding_type(Option<EncodingType>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_encoding_type):<br>required: **false**<br><p>Requests Amazon S3 to encode the object keys in the response and specifies the encoding method to use. An object key can contain any Unicode character; however, the XML 1.0 parser cannot parse some characters, such as characters with an ASCII value from 0 to 10. For characters that are not supported in XML 1.0, you can add this parameter to request that Amazon S3 encode the keys in the response.</p><br>
    ///   - [`marker(impl Into<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::marker) / [`set_marker(Option<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_marker):<br>required: **false**<br><p>Marker is where you want Amazon S3 to start listing from. Amazon S3 starts listing after this specified key. Marker can be any key in the bucket.</p><br>
    ///   - [`max_keys(i32)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::max_keys) / [`set_max_keys(Option<i32>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_max_keys):<br>required: **false**<br><p>Sets the maximum number of keys returned in the response. By default, the action returns up to 1,000 key names. The response might contain fewer keys but will never contain more. </p><br>
    ///   - [`prefix(impl Into<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::prefix) / [`set_prefix(Option<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_prefix):<br>required: **false**<br><p>Limits the response to keys that begin with the specified prefix.</p><br>
    ///   - [`request_payer(RequestPayer)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::request_payer) / [`set_request_payer(Option<RequestPayer>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_request_payer):<br>required: **false**<br><p>Confirms that the requester knows that she or he will be charged for the list objects request. Bucket owners need not specify this parameter in their requests.</p><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><br>
    ///   - [`optional_object_attributes(OptionalObjectAttributes)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::optional_object_attributes) / [`set_optional_object_attributes(Option<Vec::<OptionalObjectAttributes>>)`](crate::operation::list_objects::builders::ListObjectsFluentBuilder::set_optional_object_attributes):<br>required: **false**<br><p>Specifies the optional fields that you want returned in the response. Fields that you do not specify are not returned.</p><br>
    /// - On success, responds with [`ListObjectsOutput`](crate::operation::list_objects::ListObjectsOutput) with field(s):
    ///   - [`is_truncated(Option<bool>)`](crate::operation::list_objects::ListObjectsOutput::is_truncated): <p>A flag that indicates whether Amazon S3 returned all of the results that satisfied the search criteria.</p>
    ///   - [`marker(Option<String>)`](crate::operation::list_objects::ListObjectsOutput::marker): <p>Indicates where in the bucket listing begins. Marker is included in the response if it was sent with the request.</p>
    ///   - [`next_marker(Option<String>)`](crate::operation::list_objects::ListObjectsOutput::next_marker): <p>When the response is truncated (the <code>IsTruncated</code> element value in the response is <code>true</code>), you can use the key name in this field as the <code>marker</code> parameter in the subsequent request to get the next set of objects. Amazon S3 lists objects in alphabetical order. </p> <note>   <p>This element is returned only if you have the <code>delimiter</code> request parameter specified. If the response does not include the <code>NextMarker</code> element and it is truncated, you can use the value of the last <code>Key</code> element in the response as the <code>marker</code> parameter in the subsequent request to get the next set of object keys.</p>  </note>
    ///   - [`contents(Option<Vec::<Object>>)`](crate::operation::list_objects::ListObjectsOutput::contents): <p>Metadata about each object returned.</p>
    ///   - [`name(Option<String>)`](crate::operation::list_objects::ListObjectsOutput::name): <p>The bucket name.</p>
    ///   - [`prefix(Option<String>)`](crate::operation::list_objects::ListObjectsOutput::prefix): <p>Keys that begin with the indicated prefix.</p>
    ///   - [`delimiter(Option<String>)`](crate::operation::list_objects::ListObjectsOutput::delimiter): <p>Causes keys that contain the same string between the prefix and the first occurrence of the delimiter to be rolled up into a single result element in the <code>CommonPrefixes</code> collection. These rolled-up keys are not returned elsewhere in the response. Each rolled-up result counts as only one return against the <code>MaxKeys</code> value.</p>
    ///   - [`max_keys(Option<i32>)`](crate::operation::list_objects::ListObjectsOutput::max_keys): <p>The maximum number of keys returned in the response body.</p>
    ///   - [`common_prefixes(Option<Vec::<CommonPrefix>>)`](crate::operation::list_objects::ListObjectsOutput::common_prefixes): <p>All of the keys (up to 1,000) rolled up in a common prefix count as a single return when calculating the number of returns. </p>  <p>A response can contain <code>CommonPrefixes</code> only if you specify a delimiter.</p>  <p> <code>CommonPrefixes</code> contains all (if there are any) keys between <code>Prefix</code> and the next occurrence of the string specified by the delimiter.</p>  <p> <code>CommonPrefixes</code> lists keys that act like subdirectories in the directory specified by <code>Prefix</code>.</p>  <p>For example, if the prefix is <code>notes/</code> and the delimiter is a slash (<code>/</code>), as in <code>notes/summer/july</code>, the common prefix is <code>notes/summer/</code>. All of the keys that roll up into a common prefix count as a single return when calculating the number of returns.</p>
    ///   - [`encoding_type(Option<EncodingType>)`](crate::operation::list_objects::ListObjectsOutput::encoding_type): <p>Encoding type used by Amazon S3 to encode object keys in the response.</p>
    ///   - [`request_charged(Option<RequestCharged>)`](crate::operation::list_objects::ListObjectsOutput::request_charged): <p>If present, indicates that the requester was successfully charged for the request.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note>
    /// - On failure, responds with [`SdkError<ListObjectsError>`](crate::operation::list_objects::ListObjectsError)
    pub fn list_objects(&self) -> crate::operation::list_objects::builders::ListObjectsFluentBuilder {
        crate::operation::list_objects::builders::ListObjectsFluentBuilder::new(self.handle.clone())
    }
}