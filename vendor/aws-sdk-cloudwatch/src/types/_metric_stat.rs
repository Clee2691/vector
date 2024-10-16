// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure defines the metric to be returned, along with the statistics, period, and units.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricStat {
    /// <p>The metric to return, including the metric name, namespace, and dimensions.</p>
    pub metric: ::std::option::Option<crate::types::Metric>,
    /// <p>The granularity, in seconds, of the returned data points. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li> <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p> </li>
    /// <li> <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p> </li>
    /// <li> <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p> </li>
    /// </ul>
    pub period: ::std::option::Option<i32>,
    /// <p>The statistic to return. It can include any CloudWatch statistic or extended statistic.</p>
    pub stat: ::std::option::Option<::std::string::String>,
    /// <p>When you are using a <code>Put</code> operation, this defines what unit you want to use when storing the metric.</p>
    /// <p>In a <code>Get</code> operation, if you omit <code>Unit</code> then all data that was collected with any unit is returned, along with the corresponding units that were specified when the data was reported to CloudWatch. If you specify a unit, the operation returns only data that was collected with that unit specified. If you specify a unit that does not match the data collected, the results of the operation are null. CloudWatch does not perform unit conversions.</p>
    pub unit: ::std::option::Option<crate::types::StandardUnit>,
}
impl MetricStat {
    /// <p>The metric to return, including the metric name, namespace, and dimensions.</p>
    pub fn metric(&self) -> ::std::option::Option<&crate::types::Metric> {
        self.metric.as_ref()
    }
    /// <p>The granularity, in seconds, of the returned data points. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li> <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p> </li>
    /// <li> <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p> </li>
    /// <li> <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p> </li>
    /// </ul>
    pub fn period(&self) -> ::std::option::Option<i32> {
        self.period
    }
    /// <p>The statistic to return. It can include any CloudWatch statistic or extended statistic.</p>
    pub fn stat(&self) -> ::std::option::Option<&str> {
        self.stat.as_deref()
    }
    /// <p>When you are using a <code>Put</code> operation, this defines what unit you want to use when storing the metric.</p>
    /// <p>In a <code>Get</code> operation, if you omit <code>Unit</code> then all data that was collected with any unit is returned, along with the corresponding units that were specified when the data was reported to CloudWatch. If you specify a unit, the operation returns only data that was collected with that unit specified. If you specify a unit that does not match the data collected, the results of the operation are null. CloudWatch does not perform unit conversions.</p>
    pub fn unit(&self) -> ::std::option::Option<&crate::types::StandardUnit> {
        self.unit.as_ref()
    }
}
impl MetricStat {
    /// Creates a new builder-style object to manufacture [`MetricStat`](crate::types::MetricStat).
    pub fn builder() -> crate::types::builders::MetricStatBuilder {
        crate::types::builders::MetricStatBuilder::default()
    }
}

/// A builder for [`MetricStat`](crate::types::MetricStat).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct MetricStatBuilder {
    pub(crate) metric: ::std::option::Option<crate::types::Metric>,
    pub(crate) period: ::std::option::Option<i32>,
    pub(crate) stat: ::std::option::Option<::std::string::String>,
    pub(crate) unit: ::std::option::Option<crate::types::StandardUnit>,
}
impl MetricStatBuilder {
    /// <p>The metric to return, including the metric name, namespace, and dimensions.</p>
    /// This field is required.
    pub fn metric(mut self, input: crate::types::Metric) -> Self {
        self.metric = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric to return, including the metric name, namespace, and dimensions.</p>
    pub fn set_metric(mut self, input: ::std::option::Option<crate::types::Metric>) -> Self {
        self.metric = input;
        self
    }
    /// <p>The metric to return, including the metric name, namespace, and dimensions.</p>
    pub fn get_metric(&self) -> &::std::option::Option<crate::types::Metric> {
        &self.metric
    }
    /// <p>The granularity, in seconds, of the returned data points. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li> <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p> </li>
    /// <li> <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p> </li>
    /// <li> <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p> </li>
    /// </ul>
    /// This field is required.
    pub fn period(mut self, input: i32) -> Self {
        self.period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The granularity, in seconds, of the returned data points. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li> <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p> </li>
    /// <li> <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p> </li>
    /// <li> <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p> </li>
    /// </ul>
    pub fn set_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.period = input;
        self
    }
    /// <p>The granularity, in seconds, of the returned data points. For metrics with regular resolution, a period can be as short as one minute (60 seconds) and must be a multiple of 60. For high-resolution metrics that are collected at intervals of less than one minute, the period can be 1, 5, 10, 30, 60, or any multiple of 60. High-resolution metrics are those metrics stored by a <code>PutMetricData</code> call that includes a <code>StorageResolution</code> of 1 second.</p>
    /// <p>If the <code>StartTime</code> parameter specifies a time stamp that is greater than 3 hours ago, you must specify the period as follows or no data points in that time range is returned:</p>
    /// <ul>
    /// <li> <p>Start time between 3 hours and 15 days ago - Use a multiple of 60 seconds (1 minute).</p> </li>
    /// <li> <p>Start time between 15 and 63 days ago - Use a multiple of 300 seconds (5 minutes).</p> </li>
    /// <li> <p>Start time greater than 63 days ago - Use a multiple of 3600 seconds (1 hour).</p> </li>
    /// </ul>
    pub fn get_period(&self) -> &::std::option::Option<i32> {
        &self.period
    }
    /// <p>The statistic to return. It can include any CloudWatch statistic or extended statistic.</p>
    /// This field is required.
    pub fn stat(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stat = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The statistic to return. It can include any CloudWatch statistic or extended statistic.</p>
    pub fn set_stat(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stat = input;
        self
    }
    /// <p>The statistic to return. It can include any CloudWatch statistic or extended statistic.</p>
    pub fn get_stat(&self) -> &::std::option::Option<::std::string::String> {
        &self.stat
    }
    /// <p>When you are using a <code>Put</code> operation, this defines what unit you want to use when storing the metric.</p>
    /// <p>In a <code>Get</code> operation, if you omit <code>Unit</code> then all data that was collected with any unit is returned, along with the corresponding units that were specified when the data was reported to CloudWatch. If you specify a unit, the operation returns only data that was collected with that unit specified. If you specify a unit that does not match the data collected, the results of the operation are null. CloudWatch does not perform unit conversions.</p>
    pub fn unit(mut self, input: crate::types::StandardUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>When you are using a <code>Put</code> operation, this defines what unit you want to use when storing the metric.</p>
    /// <p>In a <code>Get</code> operation, if you omit <code>Unit</code> then all data that was collected with any unit is returned, along with the corresponding units that were specified when the data was reported to CloudWatch. If you specify a unit, the operation returns only data that was collected with that unit specified. If you specify a unit that does not match the data collected, the results of the operation are null. CloudWatch does not perform unit conversions.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::StandardUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>When you are using a <code>Put</code> operation, this defines what unit you want to use when storing the metric.</p>
    /// <p>In a <code>Get</code> operation, if you omit <code>Unit</code> then all data that was collected with any unit is returned, along with the corresponding units that were specified when the data was reported to CloudWatch. If you specify a unit, the operation returns only data that was collected with that unit specified. If you specify a unit that does not match the data collected, the results of the operation are null. CloudWatch does not perform unit conversions.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::StandardUnit> {
        &self.unit
    }
    /// Consumes the builder and constructs a [`MetricStat`](crate::types::MetricStat).
    pub fn build(self) -> crate::types::MetricStat {
        crate::types::MetricStat {
            metric: self.metric,
            period: self.period,
            stat: self.stat,
            unit: self.unit,
        }
    }
}