// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`TagLogGroup`](crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`log_group_name(impl Into<String>)`](crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder::log_group_name) / [`set_log_group_name(Option<String>)`](crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder::set_log_group_name):<br>required: **true**<br><p>The name of the log group.</p><br>
    ///   - [`tags(impl Into<String>, impl Into<String>)`](crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder::tags) / [`set_tags(Option<HashMap::<String, String>>)`](crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder::set_tags):<br>required: **true**<br><p>The key-value pairs to use for the tags.</p><br>
    /// - On success, responds with [`TagLogGroupOutput`](crate::operation::tag_log_group::TagLogGroupOutput)
    /// - On failure, responds with [`SdkError<TagLogGroupError>`](crate::operation::tag_log_group::TagLogGroupError)
    #[deprecated(note = "Please use the generic tagging API TagResource")]
    pub fn tag_log_group(&self) -> crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder {
        crate::operation::tag_log_group::builders::TagLogGroupFluentBuilder::new(self.handle.clone())
    }
}