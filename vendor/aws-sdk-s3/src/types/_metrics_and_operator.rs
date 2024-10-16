// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A conjunction (logical AND) of predicates, which is used in evaluating a metrics filter. The operator must have at least two predicates, and an object must match all of the predicates in order for the filter to apply.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricsAndOperator {
    /// <p>The prefix used when evaluating an AND predicate.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>The list of tags used when evaluating an AND predicate.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The access point ARN used when evaluating an <code>AND</code> predicate.</p>
    pub access_point_arn: ::std::option::Option<::std::string::String>,
}
impl MetricsAndOperator {
    /// <p>The prefix used when evaluating an AND predicate.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>The list of tags used when evaluating an AND predicate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The access point ARN used when evaluating an <code>AND</code> predicate.</p>
    pub fn access_point_arn(&self) -> ::std::option::Option<&str> {
        self.access_point_arn.as_deref()
    }
}
impl MetricsAndOperator {
    /// Creates a new builder-style object to manufacture [`MetricsAndOperator`](crate::types::MetricsAndOperator).
    pub fn builder() -> crate::types::builders::MetricsAndOperatorBuilder {
        crate::types::builders::MetricsAndOperatorBuilder::default()
    }
}

/// A builder for [`MetricsAndOperator`](crate::types::MetricsAndOperator).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct MetricsAndOperatorBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) access_point_arn: ::std::option::Option<::std::string::String>,
}
impl MetricsAndOperatorBuilder {
    /// <p>The prefix used when evaluating an AND predicate.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix used when evaluating an AND predicate.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The prefix used when evaluating an AND predicate.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of tags used when evaluating an AND predicate.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of tags used when evaluating an AND predicate.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of tags used when evaluating an AND predicate.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The access point ARN used when evaluating an <code>AND</code> predicate.</p>
    pub fn access_point_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_point_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The access point ARN used when evaluating an <code>AND</code> predicate.</p>
    pub fn set_access_point_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_point_arn = input;
        self
    }
    /// <p>The access point ARN used when evaluating an <code>AND</code> predicate.</p>
    pub fn get_access_point_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_point_arn
    }
    /// Consumes the builder and constructs a [`MetricsAndOperator`](crate::types::MetricsAndOperator).
    pub fn build(self) -> crate::types::MetricsAndOperator {
        crate::types::MetricsAndOperator {
            prefix: self.prefix,
            tags: self.tags,
            access_point_arn: self.access_point_arn,
        }
    }
}