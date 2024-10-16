// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::put_bucket_ownership_controls::_put_bucket_ownership_controls_output::PutBucketOwnershipControlsOutputBuilder;

pub use crate::operation::put_bucket_ownership_controls::_put_bucket_ownership_controls_input::PutBucketOwnershipControlsInputBuilder;

impl PutBucketOwnershipControlsInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.put_bucket_ownership_controls();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `PutBucketOwnershipControls`.
///
/// <note>
/// <p>This operation is not supported by directory buckets.</p>
/// </note>
/// <p>Creates or modifies <code>OwnershipControls</code> for an Amazon S3 bucket. To use this operation, you must have the <code>s3:PutBucketOwnershipControls</code> permission. For more information about Amazon S3 permissions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/using-with-s3-actions.html">Specifying permissions in a policy</a>. </p>
/// <p>For information about Amazon S3 Object Ownership, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/about-object-ownership.html">Using object ownership</a>. </p>
/// <p>The following operations are related to <code>PutBucketOwnershipControls</code>:</p>
/// <ul>
/// <li> <p> <code>GetBucketOwnershipControls</code> </p> </li>
/// <li> <p> <code>DeleteBucketOwnershipControls</code> </p> </li>
/// </ul>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct PutBucketOwnershipControlsFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::put_bucket_ownership_controls::builders::PutBucketOwnershipControlsInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsOutput,
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsError,
    > for PutBucketOwnershipControlsFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsOutput,
            crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl PutBucketOwnershipControlsFluentBuilder {
    /// Creates a new `PutBucketOwnershipControls`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the PutBucketOwnershipControls as a reference.
    pub fn as_input(&self) -> &crate::operation::put_bucket_ownership_controls::builders::PutBucketOwnershipControlsInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControls::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControls::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsOutput,
        crate::operation::put_bucket_ownership_controls::PutBucketOwnershipControlsError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl Into<crate::config::Builder>) -> Self {
        self.set_config_override(Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The name of the Amazon S3 bucket whose <code>OwnershipControls</code> you want to set.</p>
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.bucket(input.into());
        self
    }
    /// <p>The name of the Amazon S3 bucket whose <code>OwnershipControls</code> you want to set.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_bucket(input);
        self
    }
    /// <p>The name of the Amazon S3 bucket whose <code>OwnershipControls</code> you want to set.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_bucket()
    }
    /// <p>The MD5 hash of the <code>OwnershipControls</code> request body. </p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn content_md5(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.content_md5(input.into());
        self
    }
    /// <p>The MD5 hash of the <code>OwnershipControls</code> request body. </p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn set_content_md5(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_content_md5(input);
        self
    }
    /// <p>The MD5 hash of the <code>OwnershipControls</code> request body. </p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn get_content_md5(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_content_md5()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.expected_bucket_owner(input.into());
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_expected_bucket_owner(input);
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_expected_bucket_owner()
    }
    /// <p>The <code>OwnershipControls</code> (BucketOwnerEnforced, BucketOwnerPreferred, or ObjectWriter) that you want to apply to this Amazon S3 bucket.</p>
    pub fn ownership_controls(mut self, input: crate::types::OwnershipControls) -> Self {
        self.inner = self.inner.ownership_controls(input);
        self
    }
    /// <p>The <code>OwnershipControls</code> (BucketOwnerEnforced, BucketOwnerPreferred, or ObjectWriter) that you want to apply to this Amazon S3 bucket.</p>
    pub fn set_ownership_controls(mut self, input: ::std::option::Option<crate::types::OwnershipControls>) -> Self {
        self.inner = self.inner.set_ownership_controls(input);
        self
    }
    /// <p>The <code>OwnershipControls</code> (BucketOwnerEnforced, BucketOwnerPreferred, or ObjectWriter) that you want to apply to this Amazon S3 bucket.</p>
    pub fn get_ownership_controls(&self) -> &::std::option::Option<crate::types::OwnershipControls> {
        self.inner.get_ownership_controls()
    }
}