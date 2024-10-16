// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`DeleteRetentionPolicy`](crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`log_group_name(impl Into<String>)`](crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyFluentBuilder::log_group_name) / [`set_log_group_name(Option<String>)`](crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyFluentBuilder::set_log_group_name):<br>required: **true**<br><p>The name of the log group.</p><br>
    /// - On success, responds with [`DeleteRetentionPolicyOutput`](crate::operation::delete_retention_policy::DeleteRetentionPolicyOutput)
    /// - On failure, responds with [`SdkError<DeleteRetentionPolicyError>`](crate::operation::delete_retention_policy::DeleteRetentionPolicyError)
    pub fn delete_retention_policy(&self) -> crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyFluentBuilder {
        crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyFluentBuilder::new(self.handle.clone())
    }
}