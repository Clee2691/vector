// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetMetricStream`](crate::operation::get_metric_stream::builders::GetMetricStreamFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`name(impl Into<String>)`](crate::operation::get_metric_stream::builders::GetMetricStreamFluentBuilder::name) / [`set_name(Option<String>)`](crate::operation::get_metric_stream::builders::GetMetricStreamFluentBuilder::set_name):<br>required: **true**<br><p>The name of the metric stream to retrieve information about.</p><br>
    /// - On success, responds with [`GetMetricStreamOutput`](crate::operation::get_metric_stream::GetMetricStreamOutput) with field(s):
    ///   - [`arn(Option<String>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::arn): <p>The ARN of the metric stream.</p>
    ///   - [`name(Option<String>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::name): <p>The name of the metric stream.</p>
    ///   - [`include_filters(Option<Vec::<MetricStreamFilter>>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::include_filters): <p>If this array of metric namespaces is present, then these namespaces are the only metric namespaces that are streamed by this metric stream.</p>
    ///   - [`exclude_filters(Option<Vec::<MetricStreamFilter>>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::exclude_filters): <p>If this array of metric namespaces is present, then these namespaces are the only metric namespaces that are not streamed by this metric stream. In this case, all other metric namespaces in the account are streamed by this metric stream.</p>
    ///   - [`firehose_arn(Option<String>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::firehose_arn): <p>The ARN of the Amazon Kinesis Data Firehose delivery stream that is used by this metric stream.</p>
    ///   - [`role_arn(Option<String>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::role_arn): <p>The ARN of the IAM role that is used by this metric stream.</p>
    ///   - [`state(Option<String>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::state): <p>The state of the metric stream. The possible values are <code>running</code> and <code>stopped</code>.</p>
    ///   - [`creation_date(Option<DateTime>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::creation_date): <p>The date that the metric stream was created.</p>
    ///   - [`last_update_date(Option<DateTime>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::last_update_date): <p>The date of the most recent update to the metric stream's configuration.</p>
    ///   - [`output_format(Option<MetricStreamOutputFormat>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::output_format): <p>The output format for the stream. Valid values are <code>json</code> and <code>opentelemetry0.7</code>. For more information about metric stream output formats, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-streams-formats.html">Metric streams output formats</a>.</p>
    ///   - [`statistics_configurations(Option<Vec::<MetricStreamStatisticsConfiguration>>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::statistics_configurations): <p>Each entry in this array displays information about one or more metrics that include additional statistics in the metric stream. For more information about the additional statistics, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Statistics-definitions.html.html"> CloudWatch statistics definitions</a>. </p>
    ///   - [`include_linked_accounts_metrics(Option<bool>)`](crate::operation::get_metric_stream::GetMetricStreamOutput::include_linked_accounts_metrics): <p>If this is <code>true</code> and this metric stream is in a monitoring account, then the stream includes metrics from source accounts that the monitoring account is linked to.</p>
    /// - On failure, responds with [`SdkError<GetMetricStreamError>`](crate::operation::get_metric_stream::GetMetricStreamError)
    pub fn get_metric_stream(&self) -> crate::operation::get_metric_stream::builders::GetMetricStreamFluentBuilder {
        crate::operation::get_metric_stream::builders::GetMetricStreamFluentBuilder::new(self.handle.clone())
    }
}