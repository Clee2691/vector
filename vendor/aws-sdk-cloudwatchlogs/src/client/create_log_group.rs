// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`CreateLogGroup`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`log_group_name(impl Into<String>)`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::log_group_name) / [`set_log_group_name(Option<String>)`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::set_log_group_name):<br>required: **true**<br><p>The name of the log group.</p><br>
    ///   - [`kms_key_id(impl Into<String>)`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::kms_key_id) / [`set_kms_key_id(Option<String>)`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::set_kms_key_id):<br>required: **false**<br><p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a>.</p><br>
    ///   - [`tags(impl Into<String>, impl Into<String>)`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::tags) / [`set_tags(Option<HashMap::<String, String>>)`](crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::set_tags):<br>required: **false**<br><p>The key-value pairs to use for the tags.</p>  <p>You can grant users access to certain log groups while preventing them from accessing other log groups. To do so, tag your groups and use IAM policies that refer to those tags. To assign tags when you create a log group, you must have either the <code>logs:TagResource</code> or <code>logs:TagLogGroup</code> permission. For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>. For more information about using tags to control access, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html">Controlling access to Amazon Web Services resources using tags</a>.</p><br>
    /// - On success, responds with [`CreateLogGroupOutput`](crate::operation::create_log_group::CreateLogGroupOutput)
    /// - On failure, responds with [`SdkError<CreateLogGroupError>`](crate::operation::create_log_group::CreateLogGroupError)
    pub fn create_log_group(&self) -> crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder {
        crate::operation::create_log_group::builders::CreateLogGroupFluentBuilder::new(self.handle.clone())
    }
}