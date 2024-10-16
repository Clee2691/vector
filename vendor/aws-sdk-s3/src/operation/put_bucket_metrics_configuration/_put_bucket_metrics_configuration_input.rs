// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketMetricsConfigurationInput {
    /// <p>The name of the bucket for which the metrics configuration is set.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The ID used to identify the metrics configuration. The ID has a 64 character limit and can only contain letters, numbers, periods, dashes, and underscores.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the metrics configuration.</p>
    pub metrics_configuration: ::std::option::Option<crate::types::MetricsConfiguration>,
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl PutBucketMetricsConfigurationInput {
    /// <p>The name of the bucket for which the metrics configuration is set.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The ID used to identify the metrics configuration. The ID has a 64 character limit and can only contain letters, numbers, periods, dashes, and underscores.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Specifies the metrics configuration.</p>
    pub fn metrics_configuration(&self) -> ::std::option::Option<&crate::types::MetricsConfiguration> {
        self.metrics_configuration.as_ref()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
}
impl PutBucketMetricsConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutBucketMetricsConfigurationInput`](crate::operation::put_bucket_metrics_configuration::PutBucketMetricsConfigurationInput).
    pub fn builder() -> crate::operation::put_bucket_metrics_configuration::builders::PutBucketMetricsConfigurationInputBuilder {
        crate::operation::put_bucket_metrics_configuration::builders::PutBucketMetricsConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutBucketMetricsConfigurationInput`](crate::operation::put_bucket_metrics_configuration::PutBucketMetricsConfigurationInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutBucketMetricsConfigurationInputBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) metrics_configuration: ::std::option::Option<crate::types::MetricsConfiguration>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl PutBucketMetricsConfigurationInputBuilder {
    /// <p>The name of the bucket for which the metrics configuration is set.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bucket for which the metrics configuration is set.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the bucket for which the metrics configuration is set.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The ID used to identify the metrics configuration. The ID has a 64 character limit and can only contain letters, numbers, periods, dashes, and underscores.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID used to identify the metrics configuration. The ID has a 64 character limit and can only contain letters, numbers, periods, dashes, and underscores.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID used to identify the metrics configuration. The ID has a 64 character limit and can only contain letters, numbers, periods, dashes, and underscores.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Specifies the metrics configuration.</p>
    /// This field is required.
    pub fn metrics_configuration(mut self, input: crate::types::MetricsConfiguration) -> Self {
        self.metrics_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the metrics configuration.</p>
    pub fn set_metrics_configuration(mut self, input: ::std::option::Option<crate::types::MetricsConfiguration>) -> Self {
        self.metrics_configuration = input;
        self
    }
    /// <p>Specifies the metrics configuration.</p>
    pub fn get_metrics_configuration(&self) -> &::std::option::Option<crate::types::MetricsConfiguration> {
        &self.metrics_configuration
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
    /// Consumes the builder and constructs a [`PutBucketMetricsConfigurationInput`](crate::operation::put_bucket_metrics_configuration::PutBucketMetricsConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_bucket_metrics_configuration::PutBucketMetricsConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_bucket_metrics_configuration::PutBucketMetricsConfigurationInput {
            bucket: self.bucket,
            id: self.id,
            metrics_configuration: self.metrics_configuration,
            expected_bucket_owner: self.expected_bucket_owner,
        })
    }
}