// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_list_phone_numbers_opted_out_input_input_input(
    input: &crate::operation::list_phone_numbers_opted_out::ListPhoneNumbersOptedOutInput,
) -> Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    #[allow(unused_mut)]
    let mut writer = ::aws_smithy_query::QueryWriter::new(&mut out, "ListPhoneNumbersOptedOut", "2010-03-31");
    #[allow(unused_mut)]
    let mut scope_1 = writer.prefix("nextToken");
    if let Some(var_2) = &input.next_token {
        scope_1.string(var_2);
    }
    writer.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}