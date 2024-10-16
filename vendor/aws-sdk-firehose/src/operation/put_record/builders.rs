// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::put_record::_put_record_output::PutRecordOutputBuilder;

pub use crate::operation::put_record::_put_record_input::PutRecordInputBuilder;

impl PutRecordInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::put_record::PutRecordOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::put_record::PutRecordError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.put_record();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `PutRecord`.
///
/// <p>Writes a single data record into an Amazon Kinesis Data Firehose delivery stream. To write multiple data records into a delivery stream, use <code>PutRecordBatch</code>. Applications using these operations are referred to as producers.</p>
/// <p>By default, each delivery stream can take in up to 2,000 transactions per second, 5,000 records per second, or 5 MB per second. If you use <code>PutRecord</code> and <code>PutRecordBatch</code>, the limits are an aggregate across these two operations for each delivery stream. For more information about limits and how to request an increase, see <a href="https://docs.aws.amazon.com/firehose/latest/dev/limits.html">Amazon Kinesis Data Firehose Limits</a>. </p>
/// <p>Kinesis Data Firehose accumulates and publishes a particular metric for a customer account in one minute intervals. It is possible that the bursts of incoming bytes/records ingested to a delivery stream last only for a few seconds. Due to this, the actual spikes in the traffic might not be fully visible in the customer's 1 minute CloudWatch metrics.</p>
/// <p>You must specify the name of the delivery stream and the data record when using <code>PutRecord</code>. The data record consists of a data blob that can be up to 1,000 KiB in size, and any kind of data. For example, it can be a segment from a log file, geographic location data, website clickstream data, and so on.</p>
/// <p>Kinesis Data Firehose buffers records before delivering them to the destination. To disambiguate the data blobs at the destination, a common solution is to use delimiters in the data, such as a newline (<code>\n</code>) or some other character unique within the data. This allows the consumer application to parse individual data items when reading the data from the destination.</p>
/// <p>The <code>PutRecord</code> operation returns a <code>RecordId</code>, which is a unique string assigned to each record. Producer applications can use this ID for purposes such as auditability and investigation.</p>
/// <p>If the <code>PutRecord</code> operation throws a <code>ServiceUnavailableException</code>, the API is automatically reinvoked (retried) 3 times. If the exception persists, it is possible that the throughput limits have been exceeded for the delivery stream. </p>
/// <p>Re-invoking the Put API operations (for example, PutRecord and PutRecordBatch) can result in data duplicates. For larger data assets, allow for a longer time out before retrying Put API operations.</p>
/// <p>Data records sent to Kinesis Data Firehose are stored for 24 hours from the time they are added to a delivery stream as it tries to send the records to the destination. If the destination is unreachable for more than 24 hours, the data is no longer available.</p> <important>
/// <p>Don't concatenate two or more base64 strings to form the data fields of your records. Instead, concatenate the raw data, then perform base64 encoding.</p>
/// </important>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct PutRecordFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::put_record::builders::PutRecordInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl crate::client::customize::internal::CustomizableSend<crate::operation::put_record::PutRecordOutput, crate::operation::put_record::PutRecordError>
    for PutRecordFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<crate::operation::put_record::PutRecordOutput, crate::operation::put_record::PutRecordError>,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl PutRecordFluentBuilder {
    /// Creates a new `PutRecord`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the PutRecord as a reference.
    pub fn as_input(&self) -> &crate::operation::put_record::builders::PutRecordInputBuilder {
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
        crate::operation::put_record::PutRecordOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::put_record::PutRecordError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::put_record::PutRecord::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::put_record::PutRecord::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::put_record::PutRecordOutput,
        crate::operation::put_record::PutRecordError,
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
    /// <p>The name of the delivery stream.</p>
    pub fn delivery_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.delivery_stream_name(input.into());
        self
    }
    /// <p>The name of the delivery stream.</p>
    pub fn set_delivery_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_delivery_stream_name(input);
        self
    }
    /// <p>The name of the delivery stream.</p>
    pub fn get_delivery_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_delivery_stream_name()
    }
    /// <p>The record.</p>
    pub fn record(mut self, input: crate::types::Record) -> Self {
        self.inner = self.inner.record(input);
        self
    }
    /// <p>The record.</p>
    pub fn set_record(mut self, input: ::std::option::Option<crate::types::Record>) -> Self {
        self.inner = self.inner.set_record(input);
        self
    }
    /// <p>The record.</p>
    pub fn get_record(&self) -> &::std::option::Option<crate::types::Record> {
        self.inner.get_record()
    }
}