// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateLogGroupInput {
    /// <p>The name of the log group.</p>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a>.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The key-value pairs to use for the tags.</p>
    /// <p>You can grant users access to certain log groups while preventing them from accessing other log groups. To do so, tag your groups and use IAM policies that refer to those tags. To assign tags when you create a log group, you must have either the <code>logs:TagResource</code> or <code>logs:TagLogGroup</code> permission. For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>. For more information about using tags to control access, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html">Controlling access to Amazon Web Services resources using tags</a>.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateLogGroupInput {
    /// <p>The name of the log group.</p>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a>.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The key-value pairs to use for the tags.</p>
    /// <p>You can grant users access to certain log groups while preventing them from accessing other log groups. To do so, tag your groups and use IAM policies that refer to those tags. To assign tags when you create a log group, you must have either the <code>logs:TagResource</code> or <code>logs:TagLogGroup</code> permission. For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>. For more information about using tags to control access, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html">Controlling access to Amazon Web Services resources using tags</a>.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateLogGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateLogGroupInput`](crate::operation::create_log_group::CreateLogGroupInput).
    pub fn builder() -> crate::operation::create_log_group::builders::CreateLogGroupInputBuilder {
        crate::operation::create_log_group::builders::CreateLogGroupInputBuilder::default()
    }
}

/// A builder for [`CreateLogGroupInput`](crate::operation::create_log_group::CreateLogGroupInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct CreateLogGroupInputBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateLogGroupInputBuilder {
    /// <p>The name of the log group.</p>
    /// This field is required.
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log group.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The name of the log group.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a>.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a>.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a>.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The key-value pairs to use for the tags.</p>
    /// <p>You can grant users access to certain log groups while preventing them from accessing other log groups. To do so, tag your groups and use IAM policies that refer to those tags. To assign tags when you create a log group, you must have either the <code>logs:TagResource</code> or <code>logs:TagLogGroup</code> permission. For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>. For more information about using tags to control access, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html">Controlling access to Amazon Web Services resources using tags</a>.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The key-value pairs to use for the tags.</p>
    /// <p>You can grant users access to certain log groups while preventing them from accessing other log groups. To do so, tag your groups and use IAM policies that refer to those tags. To assign tags when you create a log group, you must have either the <code>logs:TagResource</code> or <code>logs:TagLogGroup</code> permission. For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>. For more information about using tags to control access, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html">Controlling access to Amazon Web Services resources using tags</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The key-value pairs to use for the tags.</p>
    /// <p>You can grant users access to certain log groups while preventing them from accessing other log groups. To do so, tag your groups and use IAM policies that refer to those tags. To assign tags when you create a log group, you must have either the <code>logs:TagResource</code> or <code>logs:TagLogGroup</code> permission. For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>. For more information about using tags to control access, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html">Controlling access to Amazon Web Services resources using tags</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateLogGroupInput`](crate::operation::create_log_group::CreateLogGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_log_group::CreateLogGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_log_group::CreateLogGroupInput {
            log_group_name: self.log_group_name,
            kms_key_id: self.kms_key_id,
            tags: self.tags,
        })
    }
}