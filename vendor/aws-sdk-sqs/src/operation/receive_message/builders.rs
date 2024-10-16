// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::receive_message::_receive_message_output::ReceiveMessageOutputBuilder;

pub use crate::operation::receive_message::_receive_message_input::ReceiveMessageInputBuilder;

impl ReceiveMessageInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::receive_message::ReceiveMessageOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::receive_message::ReceiveMessageError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.receive_message();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `ReceiveMessage`.
///
/// <p>Retrieves one or more messages (up to 10), from the specified queue. Using the <code>WaitTimeSeconds</code> parameter enables long-poll support. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-long-polling.html">Amazon SQS Long Polling</a> in the <i>Amazon SQS Developer Guide</i>. </p>
/// <p>Short poll is the default behavior where a weighted random set of machines is sampled on a <code>ReceiveMessage</code> call. Thus, only the messages on the sampled machines are returned. If the number of messages in the queue is small (fewer than 1,000), you most likely get fewer messages than you requested per <code>ReceiveMessage</code> call. If the number of messages in the queue is extremely small, you might not receive any messages in a particular <code>ReceiveMessage</code> response. If this happens, repeat the request. </p>
/// <p>For each message returned, the response includes the following:</p>
/// <ul>
/// <li> <p>The message body.</p> </li>
/// <li> <p>An MD5 digest of the message body. For information about MD5, see <a href="https://www.ietf.org/rfc/rfc1321.txt">RFC1321</a>.</p> </li>
/// <li> <p>The <code>MessageId</code> you received when you sent the message to the queue.</p> </li>
/// <li> <p>The receipt handle.</p> </li>
/// <li> <p>The message attributes.</p> </li>
/// <li> <p>An MD5 digest of the message attributes.</p> </li>
/// </ul>
/// <p>The receipt handle is the identifier you must provide when deleting the message. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-message-identifiers.html">Queue and Message Identifiers</a> in the <i>Amazon SQS Developer Guide</i>.</p>
/// <p>You can provide the <code>VisibilityTimeout</code> parameter in your request. The parameter is applied to the messages that Amazon SQS returns in the response. If you don't include the parameter, the overall visibility timeout for the queue is used for the returned messages. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html">Visibility Timeout</a> in the <i>Amazon SQS Developer Guide</i>.</p>
/// <p>A message that isn't deleted or a message whose visibility isn't extended before the visibility timeout expires counts as a failed receive. Depending on the configuration of the queue, the message might be sent to the dead-letter queue.</p> <note>
/// <p>In the future, new attributes might be added. If you write code that calls this action, we recommend that you structure your code so that it can handle new attributes gracefully.</p>
/// </note>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct ReceiveMessageFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::receive_message::builders::ReceiveMessageInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::receive_message::ReceiveMessageOutput,
        crate::operation::receive_message::ReceiveMessageError,
    > for ReceiveMessageFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::receive_message::ReceiveMessageOutput,
            crate::operation::receive_message::ReceiveMessageError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl ReceiveMessageFluentBuilder {
    /// Creates a new `ReceiveMessage`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the ReceiveMessage as a reference.
    pub fn as_input(&self) -> &crate::operation::receive_message::builders::ReceiveMessageInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::receive_message::ReceiveMessageOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::receive_message::ReceiveMessageError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::receive_message::ReceiveMessage::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::receive_message::ReceiveMessage::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::receive_message::ReceiveMessageOutput,
        crate::operation::receive_message::ReceiveMessageError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl Into<crate::config::Builder>) -> Self {
        self.set_config_override(Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The URL of the Amazon SQS queue from which messages are received.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub fn queue_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.queue_url(input.into());
        self
    }
    /// <p>The URL of the Amazon SQS queue from which messages are received.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub fn set_queue_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_queue_url(input);
        self
    }
    /// <p>The URL of the Amazon SQS queue from which messages are received.</p>
    /// <p>Queue URLs and names are case-sensitive.</p>
    pub fn get_queue_url(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_queue_url()
    }
    /// Appends an item to `AttributeNames`.
    ///
    /// To override the contents of this collection use [`set_attribute_names`](Self::set_attribute_names).
    ///
    /// <p>A list of attributes that need to be returned along with each message. These attributes include:</p>
    /// <ul>
    /// <li> <p> <code>All</code> – Returns all values.</p> </li>
    /// <li> <p> <code>ApproximateFirstReceiveTimestamp</code> – Returns the time the message was first received from the queue (<a href="http://en.wikipedia.org/wiki/Unix_time">epoch time</a> in milliseconds).</p> </li>
    /// <li> <p> <code>ApproximateReceiveCount</code> – Returns the number of times a message has been received across all queues but not deleted.</p> </li>
    /// <li> <p> <code>AWSTraceHeader</code> – Returns the X-Ray trace header string. </p> </li>
    /// <li> <p> <code>SenderId</code> </p>
    /// <ul>
    /// <li> <p>For a user, returns the user ID, for example <code>ABCDEFGHI1JKLMNOPQ23R</code>.</p> </li>
    /// <li> <p>For an IAM role, returns the IAM role ID, for example <code>ABCDE1F2GH3I4JK5LMNOP:i-a123b456</code>.</p> </li>
    /// </ul> </li>
    /// <li> <p> <code>SentTimestamp</code> – Returns the time the message was sent to the queue (<a href="http://en.wikipedia.org/wiki/Unix_time">epoch time</a> in milliseconds).</p> </li>
    /// <li> <p> <code>SqsManagedSseEnabled</code> – Enables server-side queue encryption using SQS owned encryption keys. Only one server-side encryption option is supported per queue (for example, <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sse-existing-queue.html">SSE-KMS</a> or <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sqs-sse-queue.html">SSE-SQS</a>).</p> </li>
    /// <li> <p> <code>MessageDeduplicationId</code> – Returns the value provided by the producer that calls the <code> <code>SendMessage</code> </code> action.</p> </li>
    /// <li> <p> <code>MessageGroupId</code> – Returns the value provided by the producer that calls the <code> <code>SendMessage</code> </code> action. Messages with the same <code>MessageGroupId</code> are returned in sequence.</p> </li>
    /// <li> <p> <code>SequenceNumber</code> – Returns the value provided by Amazon SQS.</p> </li>
    /// </ul>
    pub fn attribute_names(mut self, input: crate::types::QueueAttributeName) -> Self {
        self.inner = self.inner.attribute_names(input);
        self
    }
    /// <p>A list of attributes that need to be returned along with each message. These attributes include:</p>
    /// <ul>
    /// <li> <p> <code>All</code> – Returns all values.</p> </li>
    /// <li> <p> <code>ApproximateFirstReceiveTimestamp</code> – Returns the time the message was first received from the queue (<a href="http://en.wikipedia.org/wiki/Unix_time">epoch time</a> in milliseconds).</p> </li>
    /// <li> <p> <code>ApproximateReceiveCount</code> – Returns the number of times a message has been received across all queues but not deleted.</p> </li>
    /// <li> <p> <code>AWSTraceHeader</code> – Returns the X-Ray trace header string. </p> </li>
    /// <li> <p> <code>SenderId</code> </p>
    /// <ul>
    /// <li> <p>For a user, returns the user ID, for example <code>ABCDEFGHI1JKLMNOPQ23R</code>.</p> </li>
    /// <li> <p>For an IAM role, returns the IAM role ID, for example <code>ABCDE1F2GH3I4JK5LMNOP:i-a123b456</code>.</p> </li>
    /// </ul> </li>
    /// <li> <p> <code>SentTimestamp</code> – Returns the time the message was sent to the queue (<a href="http://en.wikipedia.org/wiki/Unix_time">epoch time</a> in milliseconds).</p> </li>
    /// <li> <p> <code>SqsManagedSseEnabled</code> – Enables server-side queue encryption using SQS owned encryption keys. Only one server-side encryption option is supported per queue (for example, <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sse-existing-queue.html">SSE-KMS</a> or <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sqs-sse-queue.html">SSE-SQS</a>).</p> </li>
    /// <li> <p> <code>MessageDeduplicationId</code> – Returns the value provided by the producer that calls the <code> <code>SendMessage</code> </code> action.</p> </li>
    /// <li> <p> <code>MessageGroupId</code> – Returns the value provided by the producer that calls the <code> <code>SendMessage</code> </code> action. Messages with the same <code>MessageGroupId</code> are returned in sequence.</p> </li>
    /// <li> <p> <code>SequenceNumber</code> – Returns the value provided by Amazon SQS.</p> </li>
    /// </ul>
    pub fn set_attribute_names(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::QueueAttributeName>>) -> Self {
        self.inner = self.inner.set_attribute_names(input);
        self
    }
    /// <p>A list of attributes that need to be returned along with each message. These attributes include:</p>
    /// <ul>
    /// <li> <p> <code>All</code> – Returns all values.</p> </li>
    /// <li> <p> <code>ApproximateFirstReceiveTimestamp</code> – Returns the time the message was first received from the queue (<a href="http://en.wikipedia.org/wiki/Unix_time">epoch time</a> in milliseconds).</p> </li>
    /// <li> <p> <code>ApproximateReceiveCount</code> – Returns the number of times a message has been received across all queues but not deleted.</p> </li>
    /// <li> <p> <code>AWSTraceHeader</code> – Returns the X-Ray trace header string. </p> </li>
    /// <li> <p> <code>SenderId</code> </p>
    /// <ul>
    /// <li> <p>For a user, returns the user ID, for example <code>ABCDEFGHI1JKLMNOPQ23R</code>.</p> </li>
    /// <li> <p>For an IAM role, returns the IAM role ID, for example <code>ABCDE1F2GH3I4JK5LMNOP:i-a123b456</code>.</p> </li>
    /// </ul> </li>
    /// <li> <p> <code>SentTimestamp</code> – Returns the time the message was sent to the queue (<a href="http://en.wikipedia.org/wiki/Unix_time">epoch time</a> in milliseconds).</p> </li>
    /// <li> <p> <code>SqsManagedSseEnabled</code> – Enables server-side queue encryption using SQS owned encryption keys. Only one server-side encryption option is supported per queue (for example, <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sse-existing-queue.html">SSE-KMS</a> or <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sqs-sse-queue.html">SSE-SQS</a>).</p> </li>
    /// <li> <p> <code>MessageDeduplicationId</code> – Returns the value provided by the producer that calls the <code> <code>SendMessage</code> </code> action.</p> </li>
    /// <li> <p> <code>MessageGroupId</code> – Returns the value provided by the producer that calls the <code> <code>SendMessage</code> </code> action. Messages with the same <code>MessageGroupId</code> are returned in sequence.</p> </li>
    /// <li> <p> <code>SequenceNumber</code> – Returns the value provided by Amazon SQS.</p> </li>
    /// </ul>
    pub fn get_attribute_names(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::QueueAttributeName>> {
        self.inner.get_attribute_names()
    }
    /// Appends an item to `MessageAttributeNames`.
    ///
    /// To override the contents of this collection use [`set_message_attribute_names`](Self::set_message_attribute_names).
    ///
    /// <p>The name of the message attribute, where <i>N</i> is the index.</p>
    /// <ul>
    /// <li> <p>The name can contain alphanumeric characters and the underscore (<code>_</code>), hyphen (<code>-</code>), and period (<code>.</code>).</p> </li>
    /// <li> <p>The name is case-sensitive and must be unique among all attribute names for the message.</p> </li>
    /// <li> <p>The name must not start with AWS-reserved prefixes such as <code>AWS.</code> or <code>Amazon.</code> (or any casing variants).</p> </li>
    /// <li> <p>The name must not start or end with a period (<code>.</code>), and it should not have periods in succession (<code>..</code>).</p> </li>
    /// <li> <p>The name can be up to 256 characters long.</p> </li>
    /// </ul>
    /// <p>When using <code>ReceiveMessage</code>, you can send a list of attribute names to receive, or you can return all of the attributes by specifying <code>All</code> or <code>.*</code> in your request. You can also use all message attributes starting with a prefix, for example <code>bar.*</code>.</p>
    pub fn message_attribute_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.message_attribute_names(input.into());
        self
    }
    /// <p>The name of the message attribute, where <i>N</i> is the index.</p>
    /// <ul>
    /// <li> <p>The name can contain alphanumeric characters and the underscore (<code>_</code>), hyphen (<code>-</code>), and period (<code>.</code>).</p> </li>
    /// <li> <p>The name is case-sensitive and must be unique among all attribute names for the message.</p> </li>
    /// <li> <p>The name must not start with AWS-reserved prefixes such as <code>AWS.</code> or <code>Amazon.</code> (or any casing variants).</p> </li>
    /// <li> <p>The name must not start or end with a period (<code>.</code>), and it should not have periods in succession (<code>..</code>).</p> </li>
    /// <li> <p>The name can be up to 256 characters long.</p> </li>
    /// </ul>
    /// <p>When using <code>ReceiveMessage</code>, you can send a list of attribute names to receive, or you can return all of the attributes by specifying <code>All</code> or <code>.*</code> in your request. You can also use all message attributes starting with a prefix, for example <code>bar.*</code>.</p>
    pub fn set_message_attribute_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inner = self.inner.set_message_attribute_names(input);
        self
    }
    /// <p>The name of the message attribute, where <i>N</i> is the index.</p>
    /// <ul>
    /// <li> <p>The name can contain alphanumeric characters and the underscore (<code>_</code>), hyphen (<code>-</code>), and period (<code>.</code>).</p> </li>
    /// <li> <p>The name is case-sensitive and must be unique among all attribute names for the message.</p> </li>
    /// <li> <p>The name must not start with AWS-reserved prefixes such as <code>AWS.</code> or <code>Amazon.</code> (or any casing variants).</p> </li>
    /// <li> <p>The name must not start or end with a period (<code>.</code>), and it should not have periods in succession (<code>..</code>).</p> </li>
    /// <li> <p>The name can be up to 256 characters long.</p> </li>
    /// </ul>
    /// <p>When using <code>ReceiveMessage</code>, you can send a list of attribute names to receive, or you can return all of the attributes by specifying <code>All</code> or <code>.*</code> in your request. You can also use all message attributes starting with a prefix, for example <code>bar.*</code>.</p>
    pub fn get_message_attribute_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        self.inner.get_message_attribute_names()
    }
    /// <p>The maximum number of messages to return. Amazon SQS never returns more messages than this value (however, fewer messages might be returned). Valid values: 1 to 10. Default: 1.</p>
    pub fn max_number_of_messages(mut self, input: i32) -> Self {
        self.inner = self.inner.max_number_of_messages(input);
        self
    }
    /// <p>The maximum number of messages to return. Amazon SQS never returns more messages than this value (however, fewer messages might be returned). Valid values: 1 to 10. Default: 1.</p>
    pub fn set_max_number_of_messages(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_max_number_of_messages(input);
        self
    }
    /// <p>The maximum number of messages to return. Amazon SQS never returns more messages than this value (however, fewer messages might be returned). Valid values: 1 to 10. Default: 1.</p>
    pub fn get_max_number_of_messages(&self) -> &::std::option::Option<i32> {
        self.inner.get_max_number_of_messages()
    }
    /// <p>The duration (in seconds) that the received messages are hidden from subsequent retrieve requests after being retrieved by a <code>ReceiveMessage</code> request.</p>
    pub fn visibility_timeout(mut self, input: i32) -> Self {
        self.inner = self.inner.visibility_timeout(input);
        self
    }
    /// <p>The duration (in seconds) that the received messages are hidden from subsequent retrieve requests after being retrieved by a <code>ReceiveMessage</code> request.</p>
    pub fn set_visibility_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_visibility_timeout(input);
        self
    }
    /// <p>The duration (in seconds) that the received messages are hidden from subsequent retrieve requests after being retrieved by a <code>ReceiveMessage</code> request.</p>
    pub fn get_visibility_timeout(&self) -> &::std::option::Option<i32> {
        self.inner.get_visibility_timeout()
    }
    /// <p>The duration (in seconds) for which the call waits for a message to arrive in the queue before returning. If a message is available, the call returns sooner than <code>WaitTimeSeconds</code>. If no messages are available and the wait time expires, the call returns successfully with an empty list of messages.</p> <important>
    /// <p>To avoid HTTP errors, ensure that the HTTP response timeout for <code>ReceiveMessage</code> requests is longer than the <code>WaitTimeSeconds</code> parameter. For example, with the Java SDK, you can set HTTP transport settings using the <a href="https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/http/nio/netty/NettyNioAsyncHttpClient.html"> NettyNioAsyncHttpClient</a> for asynchronous clients, or the <a href="https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/http/apache/ApacheHttpClient.html"> ApacheHttpClient</a> for synchronous clients. </p>
    /// </important>
    pub fn wait_time_seconds(mut self, input: i32) -> Self {
        self.inner = self.inner.wait_time_seconds(input);
        self
    }
    /// <p>The duration (in seconds) for which the call waits for a message to arrive in the queue before returning. If a message is available, the call returns sooner than <code>WaitTimeSeconds</code>. If no messages are available and the wait time expires, the call returns successfully with an empty list of messages.</p> <important>
    /// <p>To avoid HTTP errors, ensure that the HTTP response timeout for <code>ReceiveMessage</code> requests is longer than the <code>WaitTimeSeconds</code> parameter. For example, with the Java SDK, you can set HTTP transport settings using the <a href="https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/http/nio/netty/NettyNioAsyncHttpClient.html"> NettyNioAsyncHttpClient</a> for asynchronous clients, or the <a href="https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/http/apache/ApacheHttpClient.html"> ApacheHttpClient</a> for synchronous clients. </p>
    /// </important>
    pub fn set_wait_time_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_wait_time_seconds(input);
        self
    }
    /// <p>The duration (in seconds) for which the call waits for a message to arrive in the queue before returning. If a message is available, the call returns sooner than <code>WaitTimeSeconds</code>. If no messages are available and the wait time expires, the call returns successfully with an empty list of messages.</p> <important>
    /// <p>To avoid HTTP errors, ensure that the HTTP response timeout for <code>ReceiveMessage</code> requests is longer than the <code>WaitTimeSeconds</code> parameter. For example, with the Java SDK, you can set HTTP transport settings using the <a href="https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/http/nio/netty/NettyNioAsyncHttpClient.html"> NettyNioAsyncHttpClient</a> for asynchronous clients, or the <a href="https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/http/apache/ApacheHttpClient.html"> ApacheHttpClient</a> for synchronous clients. </p>
    /// </important>
    pub fn get_wait_time_seconds(&self) -> &::std::option::Option<i32> {
        self.inner.get_wait_time_seconds()
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of <code>ReceiveMessage</code> calls. If a networking issue occurs after a <code>ReceiveMessage</code> action, and instead of a response you receive a generic error, it is possible to retry the same action with an identical <code>ReceiveRequestAttemptId</code> to retrieve the same set of messages, even if their visibility timeout has not yet expired.</p>
    /// <ul>
    /// <li> <p>You can use <code>ReceiveRequestAttemptId</code> only for 5 minutes after a <code>ReceiveMessage</code> action.</p> </li>
    /// <li> <p>When you set <code>FifoQueue</code>, a caller of the <code>ReceiveMessage</code> action can provide a <code>ReceiveRequestAttemptId</code> explicitly.</p> </li>
    /// <li> <p>If a caller of the <code>ReceiveMessage</code> action doesn't provide a <code>ReceiveRequestAttemptId</code>, Amazon SQS generates a <code>ReceiveRequestAttemptId</code>.</p> </li>
    /// <li> <p>It is possible to retry the <code>ReceiveMessage</code> action with the same <code>ReceiveRequestAttemptId</code> if none of the messages have been modified (deleted or had their visibility changes).</p> </li>
    /// <li> <p>During a visibility timeout, subsequent calls with the same <code>ReceiveRequestAttemptId</code> return the same messages and receipt handles. If a retry occurs within the deduplication interval, it resets the visibility timeout. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html">Visibility Timeout</a> in the <i>Amazon SQS Developer Guide</i>.</p> <important>
    /// <p>If a caller of the <code>ReceiveMessage</code> action still processes messages when the visibility timeout expires and messages become visible, another worker consuming from the same queue can receive the same messages and therefore process duplicates. Also, if a consumer whose message processing time is longer than the visibility timeout tries to delete the processed messages, the action fails with an error.</p>
    /// <p>To mitigate this effect, ensure that your application observes a safe threshold before the visibility timeout expires and extend the visibility timeout as necessary.</p>
    /// </important> </li>
    /// <li> <p>While messages with a particular <code>MessageGroupId</code> are invisible, no more messages belonging to the same <code>MessageGroupId</code> are returned until the visibility timeout expires. You can still receive messages with another <code>MessageGroupId</code> as long as it is also visible.</p> </li>
    /// <li> <p>If a caller of <code>ReceiveMessage</code> can't track the <code>ReceiveRequestAttemptId</code>, no retries work until the original visibility timeout expires. As a result, delays might occur but the messages in the queue remain in a strict order.</p> </li>
    /// </ul>
    /// <p>The maximum length of <code>ReceiveRequestAttemptId</code> is 128 characters. <code>ReceiveRequestAttemptId</code> can contain alphanumeric characters (<code>a-z</code>, <code>A-Z</code>, <code>0-9</code>) and punctuation (<code>!"#$%&amp;'()*+,-./:;&lt;=&gt;?@[\]^_`{|}~</code>).</p>
    /// <p>For best practices of using <code>ReceiveRequestAttemptId</code>, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-receiverequestattemptid-request-parameter.html">Using the ReceiveRequestAttemptId Request Parameter</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn receive_request_attempt_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.receive_request_attempt_id(input.into());
        self
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of <code>ReceiveMessage</code> calls. If a networking issue occurs after a <code>ReceiveMessage</code> action, and instead of a response you receive a generic error, it is possible to retry the same action with an identical <code>ReceiveRequestAttemptId</code> to retrieve the same set of messages, even if their visibility timeout has not yet expired.</p>
    /// <ul>
    /// <li> <p>You can use <code>ReceiveRequestAttemptId</code> only for 5 minutes after a <code>ReceiveMessage</code> action.</p> </li>
    /// <li> <p>When you set <code>FifoQueue</code>, a caller of the <code>ReceiveMessage</code> action can provide a <code>ReceiveRequestAttemptId</code> explicitly.</p> </li>
    /// <li> <p>If a caller of the <code>ReceiveMessage</code> action doesn't provide a <code>ReceiveRequestAttemptId</code>, Amazon SQS generates a <code>ReceiveRequestAttemptId</code>.</p> </li>
    /// <li> <p>It is possible to retry the <code>ReceiveMessage</code> action with the same <code>ReceiveRequestAttemptId</code> if none of the messages have been modified (deleted or had their visibility changes).</p> </li>
    /// <li> <p>During a visibility timeout, subsequent calls with the same <code>ReceiveRequestAttemptId</code> return the same messages and receipt handles. If a retry occurs within the deduplication interval, it resets the visibility timeout. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html">Visibility Timeout</a> in the <i>Amazon SQS Developer Guide</i>.</p> <important>
    /// <p>If a caller of the <code>ReceiveMessage</code> action still processes messages when the visibility timeout expires and messages become visible, another worker consuming from the same queue can receive the same messages and therefore process duplicates. Also, if a consumer whose message processing time is longer than the visibility timeout tries to delete the processed messages, the action fails with an error.</p>
    /// <p>To mitigate this effect, ensure that your application observes a safe threshold before the visibility timeout expires and extend the visibility timeout as necessary.</p>
    /// </important> </li>
    /// <li> <p>While messages with a particular <code>MessageGroupId</code> are invisible, no more messages belonging to the same <code>MessageGroupId</code> are returned until the visibility timeout expires. You can still receive messages with another <code>MessageGroupId</code> as long as it is also visible.</p> </li>
    /// <li> <p>If a caller of <code>ReceiveMessage</code> can't track the <code>ReceiveRequestAttemptId</code>, no retries work until the original visibility timeout expires. As a result, delays might occur but the messages in the queue remain in a strict order.</p> </li>
    /// </ul>
    /// <p>The maximum length of <code>ReceiveRequestAttemptId</code> is 128 characters. <code>ReceiveRequestAttemptId</code> can contain alphanumeric characters (<code>a-z</code>, <code>A-Z</code>, <code>0-9</code>) and punctuation (<code>!"#$%&amp;'()*+,-./:;&lt;=&gt;?@[\]^_`{|}~</code>).</p>
    /// <p>For best practices of using <code>ReceiveRequestAttemptId</code>, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-receiverequestattemptid-request-parameter.html">Using the ReceiveRequestAttemptId Request Parameter</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn set_receive_request_attempt_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_receive_request_attempt_id(input);
        self
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of <code>ReceiveMessage</code> calls. If a networking issue occurs after a <code>ReceiveMessage</code> action, and instead of a response you receive a generic error, it is possible to retry the same action with an identical <code>ReceiveRequestAttemptId</code> to retrieve the same set of messages, even if their visibility timeout has not yet expired.</p>
    /// <ul>
    /// <li> <p>You can use <code>ReceiveRequestAttemptId</code> only for 5 minutes after a <code>ReceiveMessage</code> action.</p> </li>
    /// <li> <p>When you set <code>FifoQueue</code>, a caller of the <code>ReceiveMessage</code> action can provide a <code>ReceiveRequestAttemptId</code> explicitly.</p> </li>
    /// <li> <p>If a caller of the <code>ReceiveMessage</code> action doesn't provide a <code>ReceiveRequestAttemptId</code>, Amazon SQS generates a <code>ReceiveRequestAttemptId</code>.</p> </li>
    /// <li> <p>It is possible to retry the <code>ReceiveMessage</code> action with the same <code>ReceiveRequestAttemptId</code> if none of the messages have been modified (deleted or had their visibility changes).</p> </li>
    /// <li> <p>During a visibility timeout, subsequent calls with the same <code>ReceiveRequestAttemptId</code> return the same messages and receipt handles. If a retry occurs within the deduplication interval, it resets the visibility timeout. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html">Visibility Timeout</a> in the <i>Amazon SQS Developer Guide</i>.</p> <important>
    /// <p>If a caller of the <code>ReceiveMessage</code> action still processes messages when the visibility timeout expires and messages become visible, another worker consuming from the same queue can receive the same messages and therefore process duplicates. Also, if a consumer whose message processing time is longer than the visibility timeout tries to delete the processed messages, the action fails with an error.</p>
    /// <p>To mitigate this effect, ensure that your application observes a safe threshold before the visibility timeout expires and extend the visibility timeout as necessary.</p>
    /// </important> </li>
    /// <li> <p>While messages with a particular <code>MessageGroupId</code> are invisible, no more messages belonging to the same <code>MessageGroupId</code> are returned until the visibility timeout expires. You can still receive messages with another <code>MessageGroupId</code> as long as it is also visible.</p> </li>
    /// <li> <p>If a caller of <code>ReceiveMessage</code> can't track the <code>ReceiveRequestAttemptId</code>, no retries work until the original visibility timeout expires. As a result, delays might occur but the messages in the queue remain in a strict order.</p> </li>
    /// </ul>
    /// <p>The maximum length of <code>ReceiveRequestAttemptId</code> is 128 characters. <code>ReceiveRequestAttemptId</code> can contain alphanumeric characters (<code>a-z</code>, <code>A-Z</code>, <code>0-9</code>) and punctuation (<code>!"#$%&amp;'()*+,-./:;&lt;=&gt;?@[\]^_`{|}~</code>).</p>
    /// <p>For best practices of using <code>ReceiveRequestAttemptId</code>, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-receiverequestattemptid-request-parameter.html">Using the ReceiveRequestAttemptId Request Parameter</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn get_receive_request_attempt_id(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_receive_request_attempt_id()
    }
}