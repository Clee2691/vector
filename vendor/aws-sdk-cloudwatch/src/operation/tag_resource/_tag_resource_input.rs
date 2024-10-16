// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagResourceInput {
    /// <p>The ARN of the CloudWatch resource that you're adding tags to.</p>
    /// <p>The ARN format of an alarm is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:alarm:<i>alarm-name</i> </code> </p>
    /// <p>The ARN format of a Contributor Insights rule is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:insight-rule/<i>insight-rule-name</i> </code> </p>
    /// <p>For more information about ARN format, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoncloudwatch.html#amazoncloudwatch-resources-for-iam-policies"> Resource Types Defined by Amazon CloudWatch</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The list of key-value pairs to associate with the alarm.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagResourceInput {
    /// <p>The ARN of the CloudWatch resource that you're adding tags to.</p>
    /// <p>The ARN format of an alarm is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:alarm:<i>alarm-name</i> </code> </p>
    /// <p>The ARN format of a Contributor Insights rule is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:insight-rule/<i>insight-rule-name</i> </code> </p>
    /// <p>For more information about ARN format, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoncloudwatch.html#amazoncloudwatch-resources-for-iam-policies"> Resource Types Defined by Amazon CloudWatch</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The list of key-value pairs to associate with the alarm.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl TagResourceInput {
    /// Creates a new builder-style object to manufacture [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
    pub fn builder() -> crate::operation::tag_resource::builders::TagResourceInputBuilder {
        crate::operation::tag_resource::builders::TagResourceInputBuilder::default()
    }
}

/// A builder for [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct TagResourceInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagResourceInputBuilder {
    /// <p>The ARN of the CloudWatch resource that you're adding tags to.</p>
    /// <p>The ARN format of an alarm is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:alarm:<i>alarm-name</i> </code> </p>
    /// <p>The ARN format of a Contributor Insights rule is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:insight-rule/<i>insight-rule-name</i> </code> </p>
    /// <p>For more information about ARN format, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoncloudwatch.html#amazoncloudwatch-resources-for-iam-policies"> Resource Types Defined by Amazon CloudWatch</a> in the <i>Amazon Web Services General Reference</i>.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the CloudWatch resource that you're adding tags to.</p>
    /// <p>The ARN format of an alarm is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:alarm:<i>alarm-name</i> </code> </p>
    /// <p>The ARN format of a Contributor Insights rule is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:insight-rule/<i>insight-rule-name</i> </code> </p>
    /// <p>For more information about ARN format, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoncloudwatch.html#amazoncloudwatch-resources-for-iam-policies"> Resource Types Defined by Amazon CloudWatch</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the CloudWatch resource that you're adding tags to.</p>
    /// <p>The ARN format of an alarm is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:alarm:<i>alarm-name</i> </code> </p>
    /// <p>The ARN format of a Contributor Insights rule is <code>arn:aws:cloudwatch:<i>Region</i>:<i>account-id</i>:insight-rule/<i>insight-rule-name</i> </code> </p>
    /// <p>For more information about ARN format, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazoncloudwatch.html#amazoncloudwatch-resources-for-iam-policies"> Resource Types Defined by Amazon CloudWatch</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of key-value pairs to associate with the alarm.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of key-value pairs to associate with the alarm.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of key-value pairs to associate with the alarm.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::tag_resource::TagResourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::tag_resource::TagResourceInput {
            resource_arn: self.resource_arn,
            tags: self.tags,
        })
    }
}