// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container for specifying S3 Intelligent-Tiering filters. The filters determine the subset of objects to which the rule applies.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IntelligentTieringAndOperator {
    /// <p>An object key name prefix that identifies the subset of objects to which the configuration applies.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>All of these tags must exist in the object's tag set in order for the configuration to apply.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl IntelligentTieringAndOperator {
    /// <p>An object key name prefix that identifies the subset of objects to which the configuration applies.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>All of these tags must exist in the object's tag set in order for the configuration to apply.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl IntelligentTieringAndOperator {
    /// Creates a new builder-style object to manufacture [`IntelligentTieringAndOperator`](crate::types::IntelligentTieringAndOperator).
    pub fn builder() -> crate::types::builders::IntelligentTieringAndOperatorBuilder {
        crate::types::builders::IntelligentTieringAndOperatorBuilder::default()
    }
}

/// A builder for [`IntelligentTieringAndOperator`](crate::types::IntelligentTieringAndOperator).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct IntelligentTieringAndOperatorBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl IntelligentTieringAndOperatorBuilder {
    /// <p>An object key name prefix that identifies the subset of objects to which the configuration applies.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An object key name prefix that identifies the subset of objects to which the configuration applies.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>An object key name prefix that identifies the subset of objects to which the configuration applies.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>All of these tags must exist in the object's tag set in order for the configuration to apply.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>All of these tags must exist in the object's tag set in order for the configuration to apply.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>All of these tags must exist in the object's tag set in order for the configuration to apply.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`IntelligentTieringAndOperator`](crate::types::IntelligentTieringAndOperator).
    pub fn build(self) -> crate::types::IntelligentTieringAndOperator {
        crate::types::IntelligentTieringAndOperator {
            prefix: self.prefix,
            tags: self.tags,
        }
    }
}