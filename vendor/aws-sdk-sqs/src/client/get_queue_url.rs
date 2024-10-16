// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetQueueUrl`](crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`queue_name(impl Into<String>)`](crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder::queue_name) / [`set_queue_name(Option<String>)`](crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder::set_queue_name):<br>required: **true**<br><p>The name of the queue whose URL must be fetched. Maximum 80 characters. Valid values: alphanumeric characters, hyphens (<code>-</code>), and underscores (<code>_</code>).</p>  <p>Queue URLs and names are case-sensitive.</p><br>
    ///   - [`queue_owner_aws_account_id(impl Into<String>)`](crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder::queue_owner_aws_account_id) / [`set_queue_owner_aws_account_id(Option<String>)`](crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder::set_queue_owner_aws_account_id):<br>required: **false**<br><p>The Amazon Web Services account ID of the account that created the queue.</p><br>
    /// - On success, responds with [`GetQueueUrlOutput`](crate::operation::get_queue_url::GetQueueUrlOutput) with field(s):
    ///   - [`queue_url(Option<String>)`](crate::operation::get_queue_url::GetQueueUrlOutput::queue_url): <p>The URL of the queue.</p>
    /// - On failure, responds with [`SdkError<GetQueueUrlError>`](crate::operation::get_queue_url::GetQueueUrlError)
    pub fn get_queue_url(&self) -> crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder {
        crate::operation::get_queue_url::builders::GetQueueUrlFluentBuilder::new(self.handle.clone())
    }
}