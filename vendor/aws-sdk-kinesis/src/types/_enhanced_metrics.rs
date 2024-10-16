// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents enhanced metrics types.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnhancedMetrics {
    /// <p>List of shard-level metrics.</p>
    /// <p>The following are the valid shard-level metrics. The value "<code>ALL</code>" enhances every metric.</p>
    /// <ul>
    /// <li> <p> <code>IncomingBytes</code> </p> </li>
    /// <li> <p> <code>IncomingRecords</code> </p> </li>
    /// <li> <p> <code>OutgoingBytes</code> </p> </li>
    /// <li> <p> <code>OutgoingRecords</code> </p> </li>
    /// <li> <p> <code>WriteProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>ReadProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>IteratorAgeMilliseconds</code> </p> </li>
    /// <li> <p> <code>ALL</code> </p> </li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kinesis/latest/dev/monitoring-with-cloudwatch.html">Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch</a> in the <i>Amazon Kinesis Data Streams Developer Guide</i>.</p>
    pub shard_level_metrics: ::std::option::Option<::std::vec::Vec<crate::types::MetricsName>>,
}
impl EnhancedMetrics {
    /// <p>List of shard-level metrics.</p>
    /// <p>The following are the valid shard-level metrics. The value "<code>ALL</code>" enhances every metric.</p>
    /// <ul>
    /// <li> <p> <code>IncomingBytes</code> </p> </li>
    /// <li> <p> <code>IncomingRecords</code> </p> </li>
    /// <li> <p> <code>OutgoingBytes</code> </p> </li>
    /// <li> <p> <code>OutgoingRecords</code> </p> </li>
    /// <li> <p> <code>WriteProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>ReadProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>IteratorAgeMilliseconds</code> </p> </li>
    /// <li> <p> <code>ALL</code> </p> </li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kinesis/latest/dev/monitoring-with-cloudwatch.html">Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch</a> in the <i>Amazon Kinesis Data Streams Developer Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.shard_level_metrics.is_none()`.
    pub fn shard_level_metrics(&self) -> &[crate::types::MetricsName] {
        self.shard_level_metrics.as_deref().unwrap_or_default()
    }
}
impl EnhancedMetrics {
    /// Creates a new builder-style object to manufacture [`EnhancedMetrics`](crate::types::EnhancedMetrics).
    pub fn builder() -> crate::types::builders::EnhancedMetricsBuilder {
        crate::types::builders::EnhancedMetricsBuilder::default()
    }
}

/// A builder for [`EnhancedMetrics`](crate::types::EnhancedMetrics).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct EnhancedMetricsBuilder {
    pub(crate) shard_level_metrics: ::std::option::Option<::std::vec::Vec<crate::types::MetricsName>>,
}
impl EnhancedMetricsBuilder {
    /// Appends an item to `shard_level_metrics`.
    ///
    /// To override the contents of this collection use [`set_shard_level_metrics`](Self::set_shard_level_metrics).
    ///
    /// <p>List of shard-level metrics.</p>
    /// <p>The following are the valid shard-level metrics. The value "<code>ALL</code>" enhances every metric.</p>
    /// <ul>
    /// <li> <p> <code>IncomingBytes</code> </p> </li>
    /// <li> <p> <code>IncomingRecords</code> </p> </li>
    /// <li> <p> <code>OutgoingBytes</code> </p> </li>
    /// <li> <p> <code>OutgoingRecords</code> </p> </li>
    /// <li> <p> <code>WriteProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>ReadProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>IteratorAgeMilliseconds</code> </p> </li>
    /// <li> <p> <code>ALL</code> </p> </li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kinesis/latest/dev/monitoring-with-cloudwatch.html">Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch</a> in the <i>Amazon Kinesis Data Streams Developer Guide</i>.</p>
    pub fn shard_level_metrics(mut self, input: crate::types::MetricsName) -> Self {
        let mut v = self.shard_level_metrics.unwrap_or_default();
        v.push(input);
        self.shard_level_metrics = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of shard-level metrics.</p>
    /// <p>The following are the valid shard-level metrics. The value "<code>ALL</code>" enhances every metric.</p>
    /// <ul>
    /// <li> <p> <code>IncomingBytes</code> </p> </li>
    /// <li> <p> <code>IncomingRecords</code> </p> </li>
    /// <li> <p> <code>OutgoingBytes</code> </p> </li>
    /// <li> <p> <code>OutgoingRecords</code> </p> </li>
    /// <li> <p> <code>WriteProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>ReadProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>IteratorAgeMilliseconds</code> </p> </li>
    /// <li> <p> <code>ALL</code> </p> </li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kinesis/latest/dev/monitoring-with-cloudwatch.html">Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch</a> in the <i>Amazon Kinesis Data Streams Developer Guide</i>.</p>
    pub fn set_shard_level_metrics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricsName>>) -> Self {
        self.shard_level_metrics = input;
        self
    }
    /// <p>List of shard-level metrics.</p>
    /// <p>The following are the valid shard-level metrics. The value "<code>ALL</code>" enhances every metric.</p>
    /// <ul>
    /// <li> <p> <code>IncomingBytes</code> </p> </li>
    /// <li> <p> <code>IncomingRecords</code> </p> </li>
    /// <li> <p> <code>OutgoingBytes</code> </p> </li>
    /// <li> <p> <code>OutgoingRecords</code> </p> </li>
    /// <li> <p> <code>WriteProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>ReadProvisionedThroughputExceeded</code> </p> </li>
    /// <li> <p> <code>IteratorAgeMilliseconds</code> </p> </li>
    /// <li> <p> <code>ALL</code> </p> </li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kinesis/latest/dev/monitoring-with-cloudwatch.html">Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch</a> in the <i>Amazon Kinesis Data Streams Developer Guide</i>.</p>
    pub fn get_shard_level_metrics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricsName>> {
        &self.shard_level_metrics
    }
    /// Consumes the builder and constructs a [`EnhancedMetrics`](crate::types::EnhancedMetrics).
    pub fn build(self) -> crate::types::EnhancedMetrics {
        crate::types::EnhancedMetrics {
            shard_level_metrics: self.shard_level_metrics,
        }
    }
}