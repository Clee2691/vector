// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInsightRuleReportOutput {
    /// <p>An array of the strings used as the keys for this rule. The keys are the dimensions used to classify contributors. If the rule contains more than one key, then each unique combination of values for the keys is counted as a unique contributor.</p>
    pub key_labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies whether this rule aggregates contributor data by COUNT or SUM.</p>
    pub aggregation_statistic: ::std::option::Option<::std::string::String>,
    /// <p>The sum of the values from all individual contributors that match the rule.</p>
    pub aggregate_value: ::std::option::Option<f64>,
    /// <p>An approximate count of the unique contributors found by this rule in this time period.</p>
    pub approximate_unique_count: ::std::option::Option<i64>,
    /// <p>An array of the unique contributors found by this rule in this time period. If the rule contains multiple keys, each combination of values for the keys counts as a unique contributor.</p>
    pub contributors: ::std::option::Option<::std::vec::Vec<crate::types::InsightRuleContributor>>,
    /// <p>A time series of metric data points that matches the time period in the rule request.</p>
    pub metric_datapoints: ::std::option::Option<::std::vec::Vec<crate::types::InsightRuleMetricDatapoint>>,
    _request_id: Option<String>,
}
impl GetInsightRuleReportOutput {
    /// <p>An array of the strings used as the keys for this rule. The keys are the dimensions used to classify contributors. If the rule contains more than one key, then each unique combination of values for the keys is counted as a unique contributor.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.key_labels.is_none()`.
    pub fn key_labels(&self) -> &[::std::string::String] {
        self.key_labels.as_deref().unwrap_or_default()
    }
    /// <p>Specifies whether this rule aggregates contributor data by COUNT or SUM.</p>
    pub fn aggregation_statistic(&self) -> ::std::option::Option<&str> {
        self.aggregation_statistic.as_deref()
    }
    /// <p>The sum of the values from all individual contributors that match the rule.</p>
    pub fn aggregate_value(&self) -> ::std::option::Option<f64> {
        self.aggregate_value
    }
    /// <p>An approximate count of the unique contributors found by this rule in this time period.</p>
    pub fn approximate_unique_count(&self) -> ::std::option::Option<i64> {
        self.approximate_unique_count
    }
    /// <p>An array of the unique contributors found by this rule in this time period. If the rule contains multiple keys, each combination of values for the keys counts as a unique contributor.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.contributors.is_none()`.
    pub fn contributors(&self) -> &[crate::types::InsightRuleContributor] {
        self.contributors.as_deref().unwrap_or_default()
    }
    /// <p>A time series of metric data points that matches the time period in the rule request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metric_datapoints.is_none()`.
    pub fn metric_datapoints(&self) -> &[crate::types::InsightRuleMetricDatapoint] {
        self.metric_datapoints.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetInsightRuleReportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetInsightRuleReportOutput {
    /// Creates a new builder-style object to manufacture [`GetInsightRuleReportOutput`](crate::operation::get_insight_rule_report::GetInsightRuleReportOutput).
    pub fn builder() -> crate::operation::get_insight_rule_report::builders::GetInsightRuleReportOutputBuilder {
        crate::operation::get_insight_rule_report::builders::GetInsightRuleReportOutputBuilder::default()
    }
}

/// A builder for [`GetInsightRuleReportOutput`](crate::operation::get_insight_rule_report::GetInsightRuleReportOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetInsightRuleReportOutputBuilder {
    pub(crate) key_labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) aggregation_statistic: ::std::option::Option<::std::string::String>,
    pub(crate) aggregate_value: ::std::option::Option<f64>,
    pub(crate) approximate_unique_count: ::std::option::Option<i64>,
    pub(crate) contributors: ::std::option::Option<::std::vec::Vec<crate::types::InsightRuleContributor>>,
    pub(crate) metric_datapoints: ::std::option::Option<::std::vec::Vec<crate::types::InsightRuleMetricDatapoint>>,
    _request_id: Option<String>,
}
impl GetInsightRuleReportOutputBuilder {
    /// Appends an item to `key_labels`.
    ///
    /// To override the contents of this collection use [`set_key_labels`](Self::set_key_labels).
    ///
    /// <p>An array of the strings used as the keys for this rule. The keys are the dimensions used to classify contributors. If the rule contains more than one key, then each unique combination of values for the keys is counted as a unique contributor.</p>
    pub fn key_labels(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.key_labels.unwrap_or_default();
        v.push(input.into());
        self.key_labels = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of the strings used as the keys for this rule. The keys are the dimensions used to classify contributors. If the rule contains more than one key, then each unique combination of values for the keys is counted as a unique contributor.</p>
    pub fn set_key_labels(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.key_labels = input;
        self
    }
    /// <p>An array of the strings used as the keys for this rule. The keys are the dimensions used to classify contributors. If the rule contains more than one key, then each unique combination of values for the keys is counted as a unique contributor.</p>
    pub fn get_key_labels(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.key_labels
    }
    /// <p>Specifies whether this rule aggregates contributor data by COUNT or SUM.</p>
    pub fn aggregation_statistic(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aggregation_statistic = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies whether this rule aggregates contributor data by COUNT or SUM.</p>
    pub fn set_aggregation_statistic(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aggregation_statistic = input;
        self
    }
    /// <p>Specifies whether this rule aggregates contributor data by COUNT or SUM.</p>
    pub fn get_aggregation_statistic(&self) -> &::std::option::Option<::std::string::String> {
        &self.aggregation_statistic
    }
    /// <p>The sum of the values from all individual contributors that match the rule.</p>
    pub fn aggregate_value(mut self, input: f64) -> Self {
        self.aggregate_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sum of the values from all individual contributors that match the rule.</p>
    pub fn set_aggregate_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.aggregate_value = input;
        self
    }
    /// <p>The sum of the values from all individual contributors that match the rule.</p>
    pub fn get_aggregate_value(&self) -> &::std::option::Option<f64> {
        &self.aggregate_value
    }
    /// <p>An approximate count of the unique contributors found by this rule in this time period.</p>
    pub fn approximate_unique_count(mut self, input: i64) -> Self {
        self.approximate_unique_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>An approximate count of the unique contributors found by this rule in this time period.</p>
    pub fn set_approximate_unique_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.approximate_unique_count = input;
        self
    }
    /// <p>An approximate count of the unique contributors found by this rule in this time period.</p>
    pub fn get_approximate_unique_count(&self) -> &::std::option::Option<i64> {
        &self.approximate_unique_count
    }
    /// Appends an item to `contributors`.
    ///
    /// To override the contents of this collection use [`set_contributors`](Self::set_contributors).
    ///
    /// <p>An array of the unique contributors found by this rule in this time period. If the rule contains multiple keys, each combination of values for the keys counts as a unique contributor.</p>
    pub fn contributors(mut self, input: crate::types::InsightRuleContributor) -> Self {
        let mut v = self.contributors.unwrap_or_default();
        v.push(input);
        self.contributors = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of the unique contributors found by this rule in this time period. If the rule contains multiple keys, each combination of values for the keys counts as a unique contributor.</p>
    pub fn set_contributors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InsightRuleContributor>>) -> Self {
        self.contributors = input;
        self
    }
    /// <p>An array of the unique contributors found by this rule in this time period. If the rule contains multiple keys, each combination of values for the keys counts as a unique contributor.</p>
    pub fn get_contributors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InsightRuleContributor>> {
        &self.contributors
    }
    /// Appends an item to `metric_datapoints`.
    ///
    /// To override the contents of this collection use [`set_metric_datapoints`](Self::set_metric_datapoints).
    ///
    /// <p>A time series of metric data points that matches the time period in the rule request.</p>
    pub fn metric_datapoints(mut self, input: crate::types::InsightRuleMetricDatapoint) -> Self {
        let mut v = self.metric_datapoints.unwrap_or_default();
        v.push(input);
        self.metric_datapoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>A time series of metric data points that matches the time period in the rule request.</p>
    pub fn set_metric_datapoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InsightRuleMetricDatapoint>>) -> Self {
        self.metric_datapoints = input;
        self
    }
    /// <p>A time series of metric data points that matches the time period in the rule request.</p>
    pub fn get_metric_datapoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InsightRuleMetricDatapoint>> {
        &self.metric_datapoints
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetInsightRuleReportOutput`](crate::operation::get_insight_rule_report::GetInsightRuleReportOutput).
    pub fn build(self) -> crate::operation::get_insight_rule_report::GetInsightRuleReportOutput {
        crate::operation::get_insight_rule_report::GetInsightRuleReportOutput {
            key_labels: self.key_labels,
            aggregation_statistic: self.aggregation_statistic,
            aggregate_value: self.aggregate_value,
            approximate_unique_count: self.approximate_unique_count,
            contributors: self.contributors,
            metric_datapoints: self.metric_datapoints,
            _request_id: self._request_id,
        }
    }
}