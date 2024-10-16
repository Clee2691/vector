// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`AddPermission`](crate::operation::add_permission::builders::AddPermissionFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`queue_url(impl Into<String>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::queue_url) / [`set_queue_url(Option<String>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::set_queue_url):<br>required: **true**<br><p>The URL of the Amazon SQS queue to which permissions are added.</p>  <p>Queue URLs and names are case-sensitive.</p><br>
    ///   - [`label(impl Into<String>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::label) / [`set_label(Option<String>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::set_label):<br>required: **true**<br><p>The unique identification of the permission you're setting (for example, <code>AliceSendMessage</code>). Maximum 80 characters. Allowed characters include alphanumeric characters, hyphens (<code>-</code>), and underscores (<code>_</code>).</p><br>
    ///   - [`aws_account_ids(impl Into<String>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::aws_account_ids) / [`set_aws_account_ids(Option<Vec::<String>>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::set_aws_account_ids):<br>required: **true**<br><p>The Amazon Web Services account numbers of the <a href="https://docs.aws.amazon.com/general/latest/gr/glos-chap.html#P">principals</a> who are to receive permission. For information about locating the Amazon Web Services account identification, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-making-api-requests.html#sqs-api-request-authentication">Your Amazon Web Services Identifiers</a> in the <i>Amazon SQS Developer Guide</i>.</p><br>
    ///   - [`actions(impl Into<String>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::actions) / [`set_actions(Option<Vec::<String>>)`](crate::operation::add_permission::builders::AddPermissionFluentBuilder::set_actions):<br>required: **true**<br><p>The action the client wants to allow for the specified principal. Valid values: the name of any action or <code>*</code>.</p>  <p>For more information about these actions, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-overview-of-managing-access.html">Overview of Managing Access Permissions to Your Amazon Simple Queue Service Resource</a> in the <i>Amazon SQS Developer Guide</i>.</p>  <p>Specifying <code>SendMessage</code>, <code>DeleteMessage</code>, or <code>ChangeMessageVisibility</code> for <code>ActionName.n</code> also grants permissions for the corresponding batch versions of those actions: <code>SendMessageBatch</code>, <code>DeleteMessageBatch</code>, and <code>ChangeMessageVisibilityBatch</code>.</p><br>
    /// - On success, responds with [`AddPermissionOutput`](crate::operation::add_permission::AddPermissionOutput)
    /// - On failure, responds with [`SdkError<AddPermissionError>`](crate::operation::add_permission::AddPermissionError)
    pub fn add_permission(&self) -> crate::operation::add_permission::builders::AddPermissionFluentBuilder {
        crate::operation::add_permission::builders::AddPermissionFluentBuilder::new(self.handle.clone())
    }
}