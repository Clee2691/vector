// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub(crate) fn reflens_describe_alarm_history_output_output_next_token(
    input: &crate::operation::describe_alarm_history::DescribeAlarmHistoryOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_describe_alarms_output_output_next_token(
    input: &crate::operation::describe_alarms::DescribeAlarmsOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_describe_anomaly_detectors_output_output_next_token(
    input: &crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_describe_insight_rules_output_output_next_token(
    input: &crate::operation::describe_insight_rules::DescribeInsightRulesOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_get_metric_data_output_output_next_token(
    input: &crate::operation::get_metric_data::GetMetricDataOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_list_dashboards_output_output_next_token(
    input: &crate::operation::list_dashboards::ListDashboardsOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_list_managed_insight_rules_output_output_next_token(
    input: &crate::operation::list_managed_insight_rules::ListManagedInsightRulesOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_list_metric_streams_output_output_next_token(
    input: &crate::operation::list_metric_streams::ListMetricStreamsOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn reflens_list_metrics_output_output_next_token(
    input: &crate::operation::list_metrics::ListMetricsOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_token {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn lens_describe_alarm_history_output_output_alarm_history_items(
    input: crate::operation::describe_alarm_history::DescribeAlarmHistoryOutput,
) -> ::std::option::Option<::std::vec::Vec<crate::types::AlarmHistoryItem>> {
    let input = match input.alarm_history_items {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn lens_describe_anomaly_detectors_output_output_anomaly_detectors(
    input: crate::operation::describe_anomaly_detectors::DescribeAnomalyDetectorsOutput,
) -> ::std::option::Option<::std::vec::Vec<crate::types::AnomalyDetector>> {
    let input = match input.anomaly_detectors {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn lens_list_dashboards_output_output_dashboard_entries(
    input: crate::operation::list_dashboards::ListDashboardsOutput,
) -> ::std::option::Option<::std::vec::Vec<crate::types::DashboardEntry>> {
    let input = match input.dashboard_entries {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}