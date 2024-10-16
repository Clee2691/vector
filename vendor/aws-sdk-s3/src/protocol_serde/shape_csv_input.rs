// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_csv_input(
    input: &crate::types::CsvInput,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    if let Some(var_1) = &input.file_header_info {
        let mut inner_writer = scope.start_el("FileHeaderInfo").finish();
        inner_writer.data(var_1.as_str());
    }
    if let Some(var_2) = &input.comments {
        let mut inner_writer = scope.start_el("Comments").finish();
        inner_writer.data(var_2.as_str());
    }
    if let Some(var_3) = &input.quote_escape_character {
        let mut inner_writer = scope.start_el("QuoteEscapeCharacter").finish();
        inner_writer.data(var_3.as_str());
    }
    if let Some(var_4) = &input.record_delimiter {
        let mut inner_writer = scope.start_el("RecordDelimiter").finish();
        inner_writer.data(var_4.as_str());
    }
    if let Some(var_5) = &input.field_delimiter {
        let mut inner_writer = scope.start_el("FieldDelimiter").finish();
        inner_writer.data(var_5.as_str());
    }
    if let Some(var_6) = &input.quote_character {
        let mut inner_writer = scope.start_el("QuoteCharacter").finish();
        inner_writer.data(var_6.as_str());
    }
    if let Some(var_7) = &input.allow_quoted_record_delimiter {
        let mut inner_writer = scope.start_el("AllowQuotedRecordDelimiter").finish();
        inner_writer.data(::aws_smithy_types::primitive::Encoder::from(*var_7).encode());
    }
    scope.finish();
    Ok(())
}