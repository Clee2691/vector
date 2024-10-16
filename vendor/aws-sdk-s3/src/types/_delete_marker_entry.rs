// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the delete marker.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMarkerEntry {
    /// <p>The account that created the delete marker.&gt;</p>
    pub owner: ::std::option::Option<crate::types::Owner>,
    /// <p>The object key.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>Version ID of an object.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the object is (true) or is not (false) the latest version of an object.</p>
    pub is_latest: ::std::option::Option<bool>,
    /// <p>Date and time when the object was last modified.</p>
    pub last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DeleteMarkerEntry {
    /// <p>The account that created the delete marker.&gt;</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::Owner> {
        self.owner.as_ref()
    }
    /// <p>The object key.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>Version ID of an object.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>Specifies whether the object is (true) or is not (false) the latest version of an object.</p>
    pub fn is_latest(&self) -> ::std::option::Option<bool> {
        self.is_latest
    }
    /// <p>Date and time when the object was last modified.</p>
    pub fn last_modified(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified.as_ref()
    }
}
impl DeleteMarkerEntry {
    /// Creates a new builder-style object to manufacture [`DeleteMarkerEntry`](crate::types::DeleteMarkerEntry).
    pub fn builder() -> crate::types::builders::DeleteMarkerEntryBuilder {
        crate::types::builders::DeleteMarkerEntryBuilder::default()
    }
}

/// A builder for [`DeleteMarkerEntry`](crate::types::DeleteMarkerEntry).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteMarkerEntryBuilder {
    pub(crate) owner: ::std::option::Option<crate::types::Owner>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) is_latest: ::std::option::Option<bool>,
    pub(crate) last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DeleteMarkerEntryBuilder {
    /// <p>The account that created the delete marker.&gt;</p>
    pub fn owner(mut self, input: crate::types::Owner) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>The account that created the delete marker.&gt;</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::Owner>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The account that created the delete marker.&gt;</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::Owner> {
        &self.owner
    }
    /// <p>The object key.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The object key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The object key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>Version ID of an object.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Version ID of an object.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>Version ID of an object.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// <p>Specifies whether the object is (true) or is not (false) the latest version of an object.</p>
    pub fn is_latest(mut self, input: bool) -> Self {
        self.is_latest = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the object is (true) or is not (false) the latest version of an object.</p>
    pub fn set_is_latest(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_latest = input;
        self
    }
    /// <p>Specifies whether the object is (true) or is not (false) the latest version of an object.</p>
    pub fn get_is_latest(&self) -> &::std::option::Option<bool> {
        &self.is_latest
    }
    /// <p>Date and time when the object was last modified.</p>
    pub fn last_modified(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>Date and time when the object was last modified.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>Date and time when the object was last modified.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified
    }
    /// Consumes the builder and constructs a [`DeleteMarkerEntry`](crate::types::DeleteMarkerEntry).
    pub fn build(self) -> crate::types::DeleteMarkerEntry {
        crate::types::DeleteMarkerEntry {
            owner: self.owner,
            key: self.key,
            version_id: self.version_id,
            is_latest: self.is_latest,
            last_modified: self.last_modified,
        }
    }
}