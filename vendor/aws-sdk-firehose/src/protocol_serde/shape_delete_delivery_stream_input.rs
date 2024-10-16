// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_delete_delivery_stream_input_input(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::operation::delete_delivery_stream::DeleteDeliveryStreamInput,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.delivery_stream_name {
        object.key("DeliveryStreamName").string(var_1.as_str());
    }
    if let Some(var_2) = &input.allow_force_delete {
        object.key("AllowForceDelete").boolean(*var_2);
    }
    Ok(())
}