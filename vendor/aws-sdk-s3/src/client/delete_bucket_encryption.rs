// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`DeleteBucketEncryption`](crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket containing the server-side encryption configuration to delete.</p><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><br>
    /// - On success, responds with [`DeleteBucketEncryptionOutput`](crate::operation::delete_bucket_encryption::DeleteBucketEncryptionOutput)
    /// - On failure, responds with [`SdkError<DeleteBucketEncryptionError>`](crate::operation::delete_bucket_encryption::DeleteBucketEncryptionError)
    pub fn delete_bucket_encryption(&self) -> crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder {
        crate::operation::delete_bucket_encryption::builders::DeleteBucketEncryptionFluentBuilder::new(self.handle.clone())
    }
}