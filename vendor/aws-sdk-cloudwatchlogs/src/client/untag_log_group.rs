// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`UntagLogGroup`](crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`log_group_name(impl Into<String>)`](crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder::log_group_name) / [`set_log_group_name(Option<String>)`](crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder::set_log_group_name):<br>required: **true**<br><p>The name of the log group.</p><br>
    ///   - [`tags(impl Into<String>)`](crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder::tags) / [`set_tags(Option<Vec::<String>>)`](crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder::set_tags):<br>required: **true**<br><p>The tag keys. The corresponding tags are removed from the log group.</p><br>
    /// - On success, responds with [`UntagLogGroupOutput`](crate::operation::untag_log_group::UntagLogGroupOutput)
    /// - On failure, responds with [`SdkError<UntagLogGroupError>`](crate::operation::untag_log_group::UntagLogGroupError)
    #[deprecated(note = "Please use the generic tagging API UntagResource")]
    pub fn untag_log_group(&self) -> crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder {
        crate::operation::untag_log_group::builders::UntagLogGroupFluentBuilder::new(self.handle.clone())
    }
}