// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_get_log_group_fields_input_input(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::operation::get_log_group_fields::GetLogGroupFieldsInput,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.log_group_name {
        object.key("logGroupName").string(var_1.as_str());
    }
    if let Some(var_2) = &input.time {
        object.key("time").number(
            #[allow(clippy::useless_conversion)]
            ::aws_smithy_types::Number::NegInt((*var_2).into()),
        );
    }
    if let Some(var_3) = &input.log_group_identifier {
        object.key("logGroupIdentifier").string(var_3.as_str());
    }
    Ok(())
}