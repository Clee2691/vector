// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Encapsulates the statistical data that CloudWatch computes from metric data.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Datapoint {
    /// <p>The time stamp used for the data point.</p>
    pub timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The number of metric values that contributed to the aggregate value of this data point.</p>
    pub sample_count: ::std::option::Option<f64>,
    /// <p>The average of the metric values that correspond to the data point.</p>
    pub average: ::std::option::Option<f64>,
    /// <p>The sum of the metric values for the data point.</p>
    pub sum: ::std::option::Option<f64>,
    /// <p>The minimum metric value for the data point.</p>
    pub minimum: ::std::option::Option<f64>,
    /// <p>The maximum metric value for the data point.</p>
    pub maximum: ::std::option::Option<f64>,
    /// <p>The standard unit for the data point.</p>
    pub unit: ::std::option::Option<crate::types::StandardUnit>,
    /// <p>The percentile statistic for the data point.</p>
    pub extended_statistics: ::std::option::Option<::std::collections::HashMap<::std::string::String, f64>>,
}
impl Datapoint {
    /// <p>The time stamp used for the data point.</p>
    pub fn timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.timestamp.as_ref()
    }
    /// <p>The number of metric values that contributed to the aggregate value of this data point.</p>
    pub fn sample_count(&self) -> ::std::option::Option<f64> {
        self.sample_count
    }
    /// <p>The average of the metric values that correspond to the data point.</p>
    pub fn average(&self) -> ::std::option::Option<f64> {
        self.average
    }
    /// <p>The sum of the metric values for the data point.</p>
    pub fn sum(&self) -> ::std::option::Option<f64> {
        self.sum
    }
    /// <p>The minimum metric value for the data point.</p>
    pub fn minimum(&self) -> ::std::option::Option<f64> {
        self.minimum
    }
    /// <p>The maximum metric value for the data point.</p>
    pub fn maximum(&self) -> ::std::option::Option<f64> {
        self.maximum
    }
    /// <p>The standard unit for the data point.</p>
    pub fn unit(&self) -> ::std::option::Option<&crate::types::StandardUnit> {
        self.unit.as_ref()
    }
    /// <p>The percentile statistic for the data point.</p>
    pub fn extended_statistics(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, f64>> {
        self.extended_statistics.as_ref()
    }
}
impl Datapoint {
    /// Creates a new builder-style object to manufacture [`Datapoint`](crate::types::Datapoint).
    pub fn builder() -> crate::types::builders::DatapointBuilder {
        crate::types::builders::DatapointBuilder::default()
    }
}

/// A builder for [`Datapoint`](crate::types::Datapoint).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DatapointBuilder {
    pub(crate) timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sample_count: ::std::option::Option<f64>,
    pub(crate) average: ::std::option::Option<f64>,
    pub(crate) sum: ::std::option::Option<f64>,
    pub(crate) minimum: ::std::option::Option<f64>,
    pub(crate) maximum: ::std::option::Option<f64>,
    pub(crate) unit: ::std::option::Option<crate::types::StandardUnit>,
    pub(crate) extended_statistics: ::std::option::Option<::std::collections::HashMap<::std::string::String, f64>>,
}
impl DatapointBuilder {
    /// <p>The time stamp used for the data point.</p>
    pub fn timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time stamp used for the data point.</p>
    pub fn set_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.timestamp = input;
        self
    }
    /// <p>The time stamp used for the data point.</p>
    pub fn get_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.timestamp
    }
    /// <p>The number of metric values that contributed to the aggregate value of this data point.</p>
    pub fn sample_count(mut self, input: f64) -> Self {
        self.sample_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of metric values that contributed to the aggregate value of this data point.</p>
    pub fn set_sample_count(mut self, input: ::std::option::Option<f64>) -> Self {
        self.sample_count = input;
        self
    }
    /// <p>The number of metric values that contributed to the aggregate value of this data point.</p>
    pub fn get_sample_count(&self) -> &::std::option::Option<f64> {
        &self.sample_count
    }
    /// <p>The average of the metric values that correspond to the data point.</p>
    pub fn average(mut self, input: f64) -> Self {
        self.average = ::std::option::Option::Some(input);
        self
    }
    /// <p>The average of the metric values that correspond to the data point.</p>
    pub fn set_average(mut self, input: ::std::option::Option<f64>) -> Self {
        self.average = input;
        self
    }
    /// <p>The average of the metric values that correspond to the data point.</p>
    pub fn get_average(&self) -> &::std::option::Option<f64> {
        &self.average
    }
    /// <p>The sum of the metric values for the data point.</p>
    pub fn sum(mut self, input: f64) -> Self {
        self.sum = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sum of the metric values for the data point.</p>
    pub fn set_sum(mut self, input: ::std::option::Option<f64>) -> Self {
        self.sum = input;
        self
    }
    /// <p>The sum of the metric values for the data point.</p>
    pub fn get_sum(&self) -> &::std::option::Option<f64> {
        &self.sum
    }
    /// <p>The minimum metric value for the data point.</p>
    pub fn minimum(mut self, input: f64) -> Self {
        self.minimum = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum metric value for the data point.</p>
    pub fn set_minimum(mut self, input: ::std::option::Option<f64>) -> Self {
        self.minimum = input;
        self
    }
    /// <p>The minimum metric value for the data point.</p>
    pub fn get_minimum(&self) -> &::std::option::Option<f64> {
        &self.minimum
    }
    /// <p>The maximum metric value for the data point.</p>
    pub fn maximum(mut self, input: f64) -> Self {
        self.maximum = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum metric value for the data point.</p>
    pub fn set_maximum(mut self, input: ::std::option::Option<f64>) -> Self {
        self.maximum = input;
        self
    }
    /// <p>The maximum metric value for the data point.</p>
    pub fn get_maximum(&self) -> &::std::option::Option<f64> {
        &self.maximum
    }
    /// <p>The standard unit for the data point.</p>
    pub fn unit(mut self, input: crate::types::StandardUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The standard unit for the data point.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::StandardUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The standard unit for the data point.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::StandardUnit> {
        &self.unit
    }
    /// Adds a key-value pair to `extended_statistics`.
    ///
    /// To override the contents of this collection use [`set_extended_statistics`](Self::set_extended_statistics).
    ///
    /// <p>The percentile statistic for the data point.</p>
    pub fn extended_statistics(mut self, k: impl ::std::convert::Into<::std::string::String>, v: f64) -> Self {
        let mut hash_map = self.extended_statistics.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.extended_statistics = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The percentile statistic for the data point.</p>
    pub fn set_extended_statistics(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, f64>>) -> Self {
        self.extended_statistics = input;
        self
    }
    /// <p>The percentile statistic for the data point.</p>
    pub fn get_extended_statistics(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, f64>> {
        &self.extended_statistics
    }
    /// Consumes the builder and constructs a [`Datapoint`](crate::types::Datapoint).
    pub fn build(self) -> crate::types::Datapoint {
        crate::types::Datapoint {
            timestamp: self.timestamp,
            sample_count: self.sample_count,
            average: self.average,
            sum: self.sum,
            minimum: self.minimum,
            maximum: self.maximum,
            unit: self.unit,
            extended_statistics: self.extended_statistics,
        }
    }
}