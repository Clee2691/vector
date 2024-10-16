// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_start_metric_streams_input_input_input(
    input: &crate::operation::start_metric_streams::StartMetricStreamsInput,
) -> Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    #[allow(unused_mut)]
    let mut writer = ::aws_smithy_query::QueryWriter::new(&mut out, "StartMetricStreams", "2010-08-01");
    #[allow(unused_mut)]
    let mut scope_1 = writer.prefix("Names");
    if let Some(var_2) = &input.names {
        let mut list_4 = scope_1.start_list(false, None);
        for item_3 in var_2 {
            #[allow(unused_mut)]
            let mut entry_5 = list_4.entry();
            entry_5.string(item_3);
        }
        list_4.finish();
    }
    writer.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}