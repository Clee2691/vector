// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_authorize_vpc_endpoint_access_input_input(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::operation::authorize_vpc_endpoint_access::AuthorizeVpcEndpointAccessInput,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.account {
        object.key("Account").string(var_1.as_str());
    }
    Ok(())
}