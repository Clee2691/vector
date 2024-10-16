// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`PutPublicAccessBlock`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the Amazon S3 bucket whose <code>PublicAccessBlock</code> configuration you want to set.</p><br>
    ///   - [`content_md5(impl Into<String>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::content_md5) / [`set_content_md5(Option<String>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::set_content_md5):<br>required: **false**<br><p>The MD5 hash of the <code>PutPublicAccessBlock</code> request body. </p>  <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p><br>
    ///   - [`checksum_algorithm(ChecksumAlgorithm)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::checksum_algorithm) / [`set_checksum_algorithm(Option<ChecksumAlgorithm>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::set_checksum_algorithm):<br>required: **false**<br><p>Indicates the algorithm used to create the checksum for the object when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>  <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p><br>
    ///   - [`public_access_block_configuration(PublicAccessBlockConfiguration)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::public_access_block_configuration) / [`set_public_access_block_configuration(Option<PublicAccessBlockConfiguration>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::set_public_access_block_configuration):<br>required: **true**<br><p>The <code>PublicAccessBlock</code> configuration that you want to apply to this Amazon S3 bucket. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status">The Meaning of "Public"</a> in the <i>Amazon S3 User Guide</i>.</p><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><br>
    /// - On success, responds with [`PutPublicAccessBlockOutput`](crate::operation::put_public_access_block::PutPublicAccessBlockOutput)
    /// - On failure, responds with [`SdkError<PutPublicAccessBlockError>`](crate::operation::put_public_access_block::PutPublicAccessBlockError)
    pub fn put_public_access_block(&self) -> crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder {
        crate::operation::put_public_access_block::builders::PutPublicAccessBlockFluentBuilder::new(self.handle.clone())
    }
}