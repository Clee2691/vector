// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_update_stream_mode_input_input(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::operation::update_stream_mode::UpdateStreamModeInput,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.stream_arn {
        object.key("StreamARN").string(var_1.as_str());
    }
    if let Some(var_2) = &input.stream_mode_details {
        #[allow(unused_mut)]
        let mut object_3 = object.key("StreamModeDetails").start_object();
        crate::protocol_serde::shape_stream_mode_details::ser_stream_mode_details(&mut object_3, var_2)?;
        object_3.finish();
    }
    Ok(())
}