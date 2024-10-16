// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAnomalyDetectorsInput {
    /// <p>Use the token returned by the previous operation to request the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in one operation. The maximum value that you can specify is 100.</p>
    /// <p>To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. </p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified namespace.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric name. If there are multiple metrics with this name in different namespaces that have anomaly detection models, they're all returned.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric dimensions. If there are multiple metrics that have these dimensions and have anomaly detection models associated, they're all returned.</p>
    pub dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
    /// <p>The anomaly detector types to request when using <code>DescribeAnomalyDetectorsInput</code>. If empty, defaults to <code>SINGLE_METRIC</code>.</p>
    pub anomaly_detector_types: ::std::option::Option<::std::vec::Vec<crate::types::AnomalyDetectorType>>,
}
impl DescribeAnomalyDetectorsInput {
    /// <p>Use the token returned by the previous operation to request the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in one operation. The maximum value that you can specify is 100.</p>
    /// <p>To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. </p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified namespace.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric name. If there are multiple metrics with this name in different namespaces that have anomaly detection models, they're all returned.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric dimensions. If there are multiple metrics that have these dimensions and have anomaly detection models associated, they're all returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dimensions.is_none()`.
    pub fn dimensions(&self) -> &[crate::types::Dimension] {
        self.dimensions.as_deref().unwrap_or_default()
    }
    /// <p>The anomaly detector types to request when using <code>DescribeAnomalyDetectorsInput</code>. If empty, defaults to <code>SINGLE_METRIC</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.anomaly_detector_types.is_none()`.
    pub fn anomaly_detector_types(&self) -> &[crate::types::AnomalyDetectorType] {
        self.anomaly_detector_types.as_deref().unwrap_or_default()
    }
}
impl DescribeAnomalyDetectorsInput {
    /// Creates a new builder-style object to manufacture [`DescribeAnomalyDetectorsInput`](crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsInput).
    pub fn builder() -> crate::operation::describe_anomaly_detectors::builders::DescribeAnomalyDetectorsInputBuilder {
        crate::operation::describe_anomaly_detectors::builders::DescribeAnomalyDetectorsInputBuilder::default()
    }
}

/// A builder for [`DescribeAnomalyDetectorsInput`](crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DescribeAnomalyDetectorsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
    pub(crate) anomaly_detector_types: ::std::option::Option<::std::vec::Vec<crate::types::AnomalyDetectorType>>,
}
impl DescribeAnomalyDetectorsInputBuilder {
    /// <p>Use the token returned by the previous operation to request the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use the token returned by the previous operation to request the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Use the token returned by the previous operation to request the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in one operation. The maximum value that you can specify is 100.</p>
    /// <p>To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. </p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in one operation. The maximum value that you can specify is 100.</p>
    /// <p>To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. </p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in one operation. The maximum value that you can specify is 100.</p>
    /// <p>To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. </p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified namespace.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified namespace.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified namespace.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric name. If there are multiple metrics with this name in different namespaces that have anomaly detection models, they're all returned.</p>
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric name. If there are multiple metrics with this name in different namespaces that have anomaly detection models, they're all returned.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric name. If there are multiple metrics with this name in different namespaces that have anomaly detection models, they're all returned.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// Appends an item to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric dimensions. If there are multiple metrics that have these dimensions and have anomaly detection models associated, they're all returned.</p>
    pub fn dimensions(mut self, input: crate::types::Dimension) -> Self {
        let mut v = self.dimensions.unwrap_or_default();
        v.push(input);
        self.dimensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric dimensions. If there are multiple metrics that have these dimensions and have anomaly detection models associated, they're all returned.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>Limits the results to only the anomaly detection models that are associated with the specified metric dimensions. If there are multiple metrics that have these dimensions and have anomaly detection models associated, they're all returned.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Dimension>> {
        &self.dimensions
    }
    /// Appends an item to `anomaly_detector_types`.
    ///
    /// To override the contents of this collection use [`set_anomaly_detector_types`](Self::set_anomaly_detector_types).
    ///
    /// <p>The anomaly detector types to request when using <code>DescribeAnomalyDetectorsInput</code>. If empty, defaults to <code>SINGLE_METRIC</code>.</p>
    pub fn anomaly_detector_types(mut self, input: crate::types::AnomalyDetectorType) -> Self {
        let mut v = self.anomaly_detector_types.unwrap_or_default();
        v.push(input);
        self.anomaly_detector_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The anomaly detector types to request when using <code>DescribeAnomalyDetectorsInput</code>. If empty, defaults to <code>SINGLE_METRIC</code>.</p>
    pub fn set_anomaly_detector_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AnomalyDetectorType>>) -> Self {
        self.anomaly_detector_types = input;
        self
    }
    /// <p>The anomaly detector types to request when using <code>DescribeAnomalyDetectorsInput</code>. If empty, defaults to <code>SINGLE_METRIC</code>.</p>
    pub fn get_anomaly_detector_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AnomalyDetectorType>> {
        &self.anomaly_detector_types
    }
    /// Consumes the builder and constructs a [`DescribeAnomalyDetectorsInput`](crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            namespace: self.namespace,
            metric_name: self.metric_name,
            dimensions: self.dimensions,
            anomaly_detector_types: self.anomaly_detector_types,
        })
    }
}