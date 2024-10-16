// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`PutBucketPolicy`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket.</p>  <p> <b>Directory buckets </b> - When you use this operation with a directory bucket, you must use path-style requests in the format <code>https://s3express-control.<i>region_code</i>.amazonaws.com/<i>bucket-name</i> </code>. Virtual-hosted-style requests aren't supported. Directory bucket names must be unique in the chosen Availability Zone. Bucket names must also follow the format <code> <i>bucket_base_name</i>--<i>az_id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az2</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i> </p><br>
    ///   - [`content_md5(impl Into<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::content_md5) / [`set_content_md5(Option<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::set_content_md5):<br>required: **false**<br><p>The MD5 hash of the request body.</p>  <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note><br>
    ///   - [`checksum_algorithm(ChecksumAlgorithm)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::checksum_algorithm) / [`set_checksum_algorithm(Option<ChecksumAlgorithm>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::set_checksum_algorithm):<br>required: **false**<br><p>Indicates the algorithm used to create the checksum for the object when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum-<i>algorithm</i> </code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>.</p>  <p>For the <code>x-amz-checksum-<i>algorithm</i> </code> header, replace <code> <i>algorithm</i> </code> with the supported algorithm from the following list: </p>  <ul>   <li> <p>CRC32</p> </li>   <li> <p>CRC32C</p> </li>   <li> <p>SHA1</p> </li>   <li> <p>SHA256</p> </li>  </ul>  <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>  <p>If the individual checksum value you provide through <code>x-amz-checksum-<i>algorithm</i> </code> doesn't match the checksum algorithm you set through <code>x-amz-sdk-checksum-algorithm</code>, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter and uses the checksum algorithm that matches the provided value in <code>x-amz-checksum-<i>algorithm</i> </code>.</p> <note>   <p>For directory buckets, when you use Amazon Web Services SDKs, <code>CRC32</code> is the default checksum algorithm that's used for performance.</p>  </note><br>
    ///   - [`confirm_remove_self_bucket_access(bool)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::confirm_remove_self_bucket_access) / [`set_confirm_remove_self_bucket_access(Option<bool>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::set_confirm_remove_self_bucket_access):<br>required: **false**<br><p>Set this parameter to true to confirm that you want to remove your permissions to change this bucket policy in the future.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note><br>
    ///   - [`policy(impl Into<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::policy) / [`set_policy(Option<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::set_policy):<br>required: **true**<br><p>The bucket policy as a JSON document.</p>  <p>For directory buckets, the only IAM action supported in the bucket policy is <code>s3express:CreateSession</code>.</p><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p> <note>   <p>For directory buckets, this header is not supported in this API operation. If you specify this header, the request fails with the HTTP status code <code>501 Not Implemented</code>.</p>  </note><br>
    /// - On success, responds with [`PutBucketPolicyOutput`](crate::operation::put_bucket_policy::PutBucketPolicyOutput)
    /// - On failure, responds with [`SdkError<PutBucketPolicyError>`](crate::operation::put_bucket_policy::PutBucketPolicyError)
    pub fn put_bucket_policy(&self) -> crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder {
        crate::operation::put_bucket_policy::builders::PutBucketPolicyFluentBuilder::new(self.handle.clone())
    }
}