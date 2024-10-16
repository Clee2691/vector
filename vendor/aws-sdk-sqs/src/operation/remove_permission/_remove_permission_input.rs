// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemovePermissionInput {
    /// <p>The URL of the Amazon SQS queue from which permissions are removed.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub queue_url: ::std::option::Option<::std::string::String>,
    /// <p>The identification of the permission to remove. This is the label added using the <code> <code>AddPermission</code> </code> action.</p>
    pub label: ::std::option::Option<::std::string::String>,
}
impl RemovePermissionInput {
    /// <p>The URL of the Amazon SQS queue from which permissions are removed.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub fn queue_url(&self) -> ::std::option::Option<&str> {
        self.queue_url.as_deref()
    }
    /// <p>The identification of the permission to remove. This is the label added using the <code> <code>AddPermission</code> </code> action.</p>
    pub fn label(&self) -> ::std::option::Option<&str> {
        self.label.as_deref()
    }
}
impl RemovePermissionInput {
    /// Creates a new builder-style object to manufacture [`RemovePermissionInput`](crate::operation::remove_permission::RemovePermissionInput).
    pub fn builder() -> crate::operation::remove_permission::builders::RemovePermissionInputBuilder {
        crate::operation::remove_permission::builders::RemovePermissionInputBuilder::default()
    }
}

/// A builder for [`RemovePermissionInput`](crate::operation::remove_permission::RemovePermissionInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct RemovePermissionInputBuilder {
    pub(crate) queue_url: ::std::option::Option<::std::string::String>,
    pub(crate) label: ::std::option::Option<::std::string::String>,
}
impl RemovePermissionInputBuilder {
    /// <p>The URL of the Amazon SQS queue from which permissions are removed.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    /// This field is required.
    pub fn queue_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the Amazon SQS queue from which permissions are removed.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub fn set_queue_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_url = input;
        self
    }
    /// <p>The URL of the Amazon SQS queue from which permissions are removed.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub fn get_queue_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_url
    }
    /// <p>The identification of the permission to remove. This is the label added using the <code> <code>AddPermission</code> </code> action.</p>
    /// This field is required.
    pub fn label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identification of the permission to remove. This is the label added using the <code> <code>AddPermission</code> </code> action.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label = input;
        self
    }
    /// <p>The identification of the permission to remove. This is the label added using the <code> <code>AddPermission</code> </code> action.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.label
    }
    /// Consumes the builder and constructs a [`RemovePermissionInput`](crate::operation::remove_permission::RemovePermissionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::remove_permission::RemovePermissionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::remove_permission::RemovePermissionInput {
            queue_url: self.queue_url,
            label: self.label,
        })
    }
}