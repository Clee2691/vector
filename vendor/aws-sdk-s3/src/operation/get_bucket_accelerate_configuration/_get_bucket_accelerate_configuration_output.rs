// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBucketAccelerateConfigurationOutput {
    /// <p>The accelerate configuration of the bucket.</p>
    pub status: ::std::option::Option<crate::types::BucketAccelerateStatus>,
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub request_charged: ::std::option::Option<crate::types::RequestCharged>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetBucketAccelerateConfigurationOutput {
    /// <p>The accelerate configuration of the bucket.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::BucketAccelerateStatus> {
        self.status.as_ref()
    }
    /// <p>If present, indicates that the requester was successfully charged for the request.</p> <note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_charged(&self) -> ::std::option::Option<&crate::types::RequestCharged> {
        self.request_charged.as_ref()
    }
}
impl crate::s3_request_id::RequestIdExt for GetBucketAccelerateConfigurationOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetBucketAccelerateConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBucketAccelerateConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetBucketAccelerateConfigurationOutput`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput).
    pub fn builder() -> crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationOutputBuilder {
        crate::operation::get_bucket_accelerate_configuration::builders::GetBucketAccelerateConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetBucketAccelerateConfigurationOutput`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetBucketAccelerateConfigurationOutputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::BucketAccelerateStatus>,
    pub(crate) request_charged: ::std::option::Option<crate::types::RequestCharged>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetBucketAccelerateConfigurationOutputBuilder {
    /// <p>The accelerate configuration of the bucket.</p>
    pub fn status(mut self, input: crate::types::BucketAccelerateStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The accelerate configuration of the bucket.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::BucketAccelerateStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The accelerate configuration of the bucket.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::BucketAccelerateStatus> {
        &self.status
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
    /// Consumes the builder and constructs a [`GetBucketAccelerateConfigurationOutput`](crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput).
    pub fn build(self) -> crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput {
        crate::operation::get_bucket_accelerate_configuration::GetBucketAccelerateConfigurationOutput {
            status: self.status,
            request_charged: self.request_charged,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}