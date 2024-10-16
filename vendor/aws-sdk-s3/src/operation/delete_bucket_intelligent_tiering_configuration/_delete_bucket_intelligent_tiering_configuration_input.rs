// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBucketIntelligentTieringConfigurationInput {
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl DeleteBucketIntelligentTieringConfigurationInput {
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DeleteBucketIntelligentTieringConfigurationInput {
    /// Creates a new builder-style object to manufacture [`DeleteBucketIntelligentTieringConfigurationInput`](crate::operation::delete_bucket_intelligent_tiering_configuration::DeleteBucketIntelligentTieringConfigurationInput).
    pub fn builder(
    ) -> crate::operation::delete_bucket_intelligent_tiering_configuration::builders::DeleteBucketIntelligentTieringConfigurationInputBuilder {
        crate::operation::delete_bucket_intelligent_tiering_configuration::builders::DeleteBucketIntelligentTieringConfigurationInputBuilder::default(
        )
    }
}

/// A builder for [`DeleteBucketIntelligentTieringConfigurationInput`](crate::operation::delete_bucket_intelligent_tiering_configuration::DeleteBucketIntelligentTieringConfigurationInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteBucketIntelligentTieringConfigurationInputBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DeleteBucketIntelligentTieringConfigurationInputBuilder {
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DeleteBucketIntelligentTieringConfigurationInput`](crate::operation::delete_bucket_intelligent_tiering_configuration::DeleteBucketIntelligentTieringConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_bucket_intelligent_tiering_configuration::DeleteBucketIntelligentTieringConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_bucket_intelligent_tiering_configuration::DeleteBucketIntelligentTieringConfigurationInput {
                bucket: self.bucket,
                id: self.id,
            },
        )
    }
}