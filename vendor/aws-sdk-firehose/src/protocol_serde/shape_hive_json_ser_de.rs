// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_hive_json_ser_de(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::types::HiveJsonSerDe,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.timestamp_formats {
        let mut array_2 = object.key("TimestampFormats").start_array();
        for item_3 in var_1 {
            {
                array_2.value().string(item_3.as_str());
            }
        }
        array_2.finish();
    }
    Ok(())
}

pub(crate) fn de_hive_json_ser_de<'a, I>(
    tokens: &mut ::std::iter::Peekable<I>,
) -> Result<Option<crate::types::HiveJsonSerDe>, ::aws_smithy_json::deserialize::error::DeserializeError>
where
    I: Iterator<Item = Result<::aws_smithy_json::deserialize::Token<'a>, ::aws_smithy_json::deserialize::error::DeserializeError>>,
{
    match tokens.next().transpose()? {
        Some(::aws_smithy_json::deserialize::Token::ValueNull { .. }) => Ok(None),
        Some(::aws_smithy_json::deserialize::Token::StartObject { .. }) => {
            #[allow(unused_mut)]
            let mut builder = crate::types::builders::HiveJsonSerDeBuilder::default();
            loop {
                match tokens.next().transpose()? {
                    Some(::aws_smithy_json::deserialize::Token::EndObject { .. }) => break,
                    Some(::aws_smithy_json::deserialize::Token::ObjectKey { key, .. }) => match key.to_unescaped()?.as_ref() {
                        "TimestampFormats" => {
                            builder = builder.set_timestamp_formats(
                                crate::protocol_serde::shape_list_of_non_empty_strings::de_list_of_non_empty_strings(tokens)?,
                            );
                        }
                        _ => ::aws_smithy_json::deserialize::token::skip_value(tokens)?,
                    },
                    other => {
                        return Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(format!(
                            "expected object key or end object, found: {:?}",
                            other
                        )))
                    }
                }
            }
            Ok(Some(builder.build()))
        }
        _ => Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(
            "expected start object or null",
        )),
    }
}