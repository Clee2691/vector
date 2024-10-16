// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetBucketAccelerateConfiguration`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket for which the accelerate configuration is retrieved.</p><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><br>
    ///   - [`request_payer(RequestPayer)`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::request_payer) / [`set_request_payer(Option<RequestPayer>)`](crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::set_request_payer):<br>required: **false**<br><p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note><br>
    /// - On success, responds with [`GetBucketAccelerateConfigurationOutput`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput) with field(s):
    ///   - [`status(Option<BucketAccelerateStatus>)`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput::status): <p>The accelerate configuration of the bucket.</p>
    ///   - [`request_charged(Option<RequestCharged>)`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput::request_charged): <p>If present, indicates that the requester was successfully charged for the request.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note>
    /// - On failure, responds with [`SdkError<GetBucketAccelerateConfigurationError>`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationError)
    pub fn get_bucket_accelerate_configuration(
        &self,
    ) -> crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder {
        crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationFluentBuilder::new(self.handle.clone())
    }
}