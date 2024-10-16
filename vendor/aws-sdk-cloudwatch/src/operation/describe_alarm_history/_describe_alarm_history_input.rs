// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAlarmHistoryInput {
    /// <p>The name of the alarm.</p>
    pub alarm_name: ::std::option::Option<::std::string::String>,
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned.</p>
    pub alarm_types: ::std::option::Option<::std::vec::Vec<crate::types::AlarmType>>,
    /// <p>The type of alarm histories to retrieve.</p>
    pub history_item_type: ::std::option::Option<crate::types::HistoryItemType>,
    /// <p>The starting date to retrieve alarm history.</p>
    pub start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ending date to retrieve alarm history.</p>
    pub end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The maximum number of alarm history records to retrieve.</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specified whether to return the newest or oldest alarm history first. Specify <code>TimestampDescending</code> to have the newest event history returned first, and specify <code>TimestampAscending</code> to have the oldest history returned first.</p>
    pub scan_by: ::std::option::Option<crate::types::ScanBy>,
}
impl DescribeAlarmHistoryInput {
    /// <p>The name of the alarm.</p>
    pub fn alarm_name(&self) -> ::std::option::Option<&str> {
        self.alarm_name.as_deref()
    }
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.alarm_types.is_none()`.
    pub fn alarm_types(&self) -> &[crate::types::AlarmType] {
        self.alarm_types.as_deref().unwrap_or_default()
    }
    /// <p>The type of alarm histories to retrieve.</p>
    pub fn history_item_type(&self) -> ::std::option::Option<&crate::types::HistoryItemType> {
        self.history_item_type.as_ref()
    }
    /// <p>The starting date to retrieve alarm history.</p>
    pub fn start_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_date.as_ref()
    }
    /// <p>The ending date to retrieve alarm history.</p>
    pub fn end_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_date.as_ref()
    }
    /// <p>The maximum number of alarm history records to retrieve.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specified whether to return the newest or oldest alarm history first. Specify <code>TimestampDescending</code> to have the newest event history returned first, and specify <code>TimestampAscending</code> to have the oldest history returned first.</p>
    pub fn scan_by(&self) -> ::std::option::Option<&crate::types::ScanBy> {
        self.scan_by.as_ref()
    }
}
impl DescribeAlarmHistoryInput {
    /// Creates a new builder-style object to manufacture [`DescribeAlarmHistoryInput`](crate::operation::describe_alarm_history::DescribeAlarmHistoryInput).
    pub fn builder() -> crate::operation::describe_alarm_history::builders::DescribeAlarmHistoryInputBuilder {
        crate::operation::describe_alarm_history::builders::DescribeAlarmHistoryInputBuilder::default()
    }
}

/// A builder for [`DescribeAlarmHistoryInput`](crate::operation::describe_alarm_history::DescribeAlarmHistoryInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DescribeAlarmHistoryInputBuilder {
    pub(crate) alarm_name: ::std::option::Option<::std::string::String>,
    pub(crate) alarm_types: ::std::option::Option<::std::vec::Vec<crate::types::AlarmType>>,
    pub(crate) history_item_type: ::std::option::Option<crate::types::HistoryItemType>,
    pub(crate) start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) scan_by: ::std::option::Option<crate::types::ScanBy>,
}
impl DescribeAlarmHistoryInputBuilder {
    /// <p>The name of the alarm.</p>
    pub fn alarm_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alarm_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the alarm.</p>
    pub fn set_alarm_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alarm_name = input;
        self
    }
    /// <p>The name of the alarm.</p>
    pub fn get_alarm_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.alarm_name
    }
    /// Appends an item to `alarm_types`.
    ///
    /// To override the contents of this collection use [`set_alarm_types`](Self::set_alarm_types).
    ///
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned.</p>
    pub fn alarm_types(mut self, input: crate::types::AlarmType) -> Self {
        let mut v = self.alarm_types.unwrap_or_default();
        v.push(input);
        self.alarm_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned.</p>
    pub fn set_alarm_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AlarmType>>) -> Self {
        self.alarm_types = input;
        self
    }
    /// <p>Use this parameter to specify whether you want the operation to return metric alarms or composite alarms. If you omit this parameter, only metric alarms are returned.</p>
    pub fn get_alarm_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AlarmType>> {
        &self.alarm_types
    }
    /// <p>The type of alarm histories to retrieve.</p>
    pub fn history_item_type(mut self, input: crate::types::HistoryItemType) -> Self {
        self.history_item_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of alarm histories to retrieve.</p>
    pub fn set_history_item_type(mut self, input: ::std::option::Option<crate::types::HistoryItemType>) -> Self {
        self.history_item_type = input;
        self
    }
    /// <p>The type of alarm histories to retrieve.</p>
    pub fn get_history_item_type(&self) -> &::std::option::Option<crate::types::HistoryItemType> {
        &self.history_item_type
    }
    /// <p>The starting date to retrieve alarm history.</p>
    pub fn start_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The starting date to retrieve alarm history.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The starting date to retrieve alarm history.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date
    }
    /// <p>The ending date to retrieve alarm history.</p>
    pub fn end_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ending date to retrieve alarm history.</p>
    pub fn set_end_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_date = input;
        self
    }
    /// <p>The ending date to retrieve alarm history.</p>
    pub fn get_end_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_date
    }
    /// <p>The maximum number of alarm history records to retrieve.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of alarm history records to retrieve.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>The maximum number of alarm history records to retrieve.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token returned by a previous call to indicate that there is more data available.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specified whether to return the newest or oldest alarm history first. Specify <code>TimestampDescending</code> to have the newest event history returned first, and specify <code>TimestampAscending</code> to have the oldest history returned first.</p>
    pub fn scan_by(mut self, input: crate::types::ScanBy) -> Self {
        self.scan_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specified whether to return the newest or oldest alarm history first. Specify <code>TimestampDescending</code> to have the newest event history returned first, and specify <code>TimestampAscending</code> to have the oldest history returned first.</p>
    pub fn set_scan_by(mut self, input: ::std::option::Option<crate::types::ScanBy>) -> Self {
        self.scan_by = input;
        self
    }
    /// <p>Specified whether to return the newest or oldest alarm history first. Specify <code>TimestampDescending</code> to have the newest event history returned first, and specify <code>TimestampAscending</code> to have the oldest history returned first.</p>
    pub fn get_scan_by(&self) -> &::std::option::Option<crate::types::ScanBy> {
        &self.scan_by
    }
    /// Consumes the builder and constructs a [`DescribeAlarmHistoryInput`](crate::operation::describe_alarm_history::DescribeAlarmHistoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_alarm_history::DescribeAlarmHistoryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_alarm_history::DescribeAlarmHistoryInput {
            alarm_name: self.alarm_name,
            alarm_types: self.alarm_types,
            history_item_type: self.history_item_type,
            start_date: self.start_date,
            end_date: self.end_date,
            max_records: self.max_records,
            next_token: self.next_token,
            scan_by: self.scan_by,
        })
    }
}