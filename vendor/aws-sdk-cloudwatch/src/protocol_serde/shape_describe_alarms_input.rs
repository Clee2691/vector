// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_describe_alarms_input_input_input(
    input: &crate::operation::describe_alarms::DescribeAlarmsInput,
) -> Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    #[allow(unused_mut)]
    let mut writer = ::aws_smithy_query::QueryWriter::new(&mut out, "DescribeAlarms", "2010-08-01");
    #[allow(unused_mut)]
    let mut scope_1 = writer.prefix("AlarmNames");
    if let Some(var_2) = &input.alarm_names {
        let mut list_4 = scope_1.start_list(false, None);
        for item_3 in var_2 {
            #[allow(unused_mut)]
            let mut entry_5 = list_4.entry();
            entry_5.string(item_3);
        }
        list_4.finish();
    }
    #[allow(unused_mut)]
    let mut scope_6 = writer.prefix("AlarmNamePrefix");
    if let Some(var_7) = &input.alarm_name_prefix {
        scope_6.string(var_7);
    }
    #[allow(unused_mut)]
    let mut scope_8 = writer.prefix("AlarmTypes");
    if let Some(var_9) = &input.alarm_types {
        let mut list_11 = scope_8.start_list(false, None);
        for item_10 in var_9 {
            #[allow(unused_mut)]
            let mut entry_12 = list_11.entry();
            entry_12.string(item_10.as_str());
        }
        list_11.finish();
    }
    #[allow(unused_mut)]
    let mut scope_13 = writer.prefix("ChildrenOfAlarmName");
    if let Some(var_14) = &input.children_of_alarm_name {
        scope_13.string(var_14);
    }
    #[allow(unused_mut)]
    let mut scope_15 = writer.prefix("ParentsOfAlarmName");
    if let Some(var_16) = &input.parents_of_alarm_name {
        scope_15.string(var_16);
    }
    #[allow(unused_mut)]
    let mut scope_17 = writer.prefix("StateValue");
    if let Some(var_18) = &input.state_value {
        scope_17.string(var_18.as_str());
    }
    #[allow(unused_mut)]
    let mut scope_19 = writer.prefix("ActionPrefix");
    if let Some(var_20) = &input.action_prefix {
        scope_19.string(var_20);
    }
    #[allow(unused_mut)]
    let mut scope_21 = writer.prefix("MaxRecords");
    if let Some(var_22) = &input.max_records {
        scope_21.number(
            #[allow(clippy::useless_conversion)]
            ::aws_smithy_types::Number::NegInt((*var_22).into()),
        );
    }
    #[allow(unused_mut)]
    let mut scope_23 = writer.prefix("NextToken");
    if let Some(var_24) = &input.next_token {
        scope_23.string(var_24);
    }
    writer.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}