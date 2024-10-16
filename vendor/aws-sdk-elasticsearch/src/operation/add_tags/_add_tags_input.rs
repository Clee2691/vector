// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>AddTags</code></code> operation. Specify the tags that you want to attach to the Elasticsearch domain.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddTagsInput {
    /// <p> Specify the <code>ARN</code> for which you want to add the tags.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p> List of <code>Tag</code> that need to be added for the Elasticsearch domain. </p>
    pub tag_list: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AddTagsInput {
    /// <p> Specify the <code>ARN</code> for which you want to add the tags.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p> List of <code>Tag</code> that need to be added for the Elasticsearch domain. </p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_list.is_none()`.
    pub fn tag_list(&self) -> &[crate::types::Tag] {
        self.tag_list.as_deref().unwrap_or_default()
    }
}
impl AddTagsInput {
    /// Creates a new builder-style object to manufacture [`AddTagsInput`](crate::operation::add_tags::AddTagsInput).
    pub fn builder() -> crate::operation::add_tags::builders::AddTagsInputBuilder {
        crate::operation::add_tags::builders::AddTagsInputBuilder::default()
    }
}

/// A builder for [`AddTagsInput`](crate::operation::add_tags::AddTagsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct AddTagsInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) tag_list: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AddTagsInputBuilder {
    /// <p> Specify the <code>ARN</code> for which you want to add the tags.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p> Specify the <code>ARN</code> for which you want to add the tags.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p> Specify the <code>ARN</code> for which you want to add the tags.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Appends an item to `tag_list`.
    ///
    /// To override the contents of this collection use [`set_tag_list`](Self::set_tag_list).
    ///
    /// <p> List of <code>Tag</code> that need to be added for the Elasticsearch domain. </p>
    pub fn tag_list(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tag_list.unwrap_or_default();
        v.push(input);
        self.tag_list = ::std::option::Option::Some(v);
        self
    }
    /// <p> List of <code>Tag</code> that need to be added for the Elasticsearch domain. </p>
    pub fn set_tag_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tag_list = input;
        self
    }
    /// <p> List of <code>Tag</code> that need to be added for the Elasticsearch domain. </p>
    pub fn get_tag_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tag_list
    }
    /// Consumes the builder and constructs a [`AddTagsInput`](crate::operation::add_tags::AddTagsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::add_tags::AddTagsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::add_tags::AddTagsInput {
            arn: self.arn,
            tag_list: self.tag_list,
        })
    }
}