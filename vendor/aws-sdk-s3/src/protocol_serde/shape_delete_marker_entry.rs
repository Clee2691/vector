// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::needless_question_mark)]
pub fn de_delete_marker_entry(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::DeleteMarkerEntry, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::DeleteMarkerEntry::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("Owner") /* Owner com.amazonaws.s3#DeleteMarkerEntry$Owner */ =>  {
                let var_1 =
                    Some(
                        crate::protocol_serde::shape_owner::de_owner(&mut tag)
                        ?
                    )
                ;
                builder = builder.set_owner(var_1);
            }
            ,
            s if s.matches("Key") /* Key com.amazonaws.s3#DeleteMarkerEntry$Key */ =>  {
                let var_2 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_key(var_2);
            }
            ,
            s if s.matches("VersionId") /* VersionId com.amazonaws.s3#DeleteMarkerEntry$VersionId */ =>  {
                let var_3 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_version_id(var_3);
            }
            ,
            s if s.matches("IsLatest") /* IsLatest com.amazonaws.s3#DeleteMarkerEntry$IsLatest */ =>  {
                let var_4 =
                    Some(
                         {
                            <bool as ::aws_smithy_types::primitive::Parse>::parse_smithy_primitive(
                                ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            )
                            .map_err(|_|::aws_smithy_xml::decode::XmlDecodeError::custom("expected (boolean: `com.amazonaws.s3#IsLatest`)"))
                        }
                        ?
                    )
                ;
                builder = builder.set_is_latest(var_4);
            }
            ,
            s if s.matches("LastModified") /* LastModified com.amazonaws.s3#DeleteMarkerEntry$LastModified */ =>  {
                let var_5 =
                    Some(
                        ::aws_smithy_types::DateTime::from_str(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            , ::aws_smithy_types::date_time::Format::DateTimeWithOffset
                        )
                        .map_err(|_|::aws_smithy_xml::decode::XmlDecodeError::custom("expected (timestamp: `com.amazonaws.s3#LastModified`)"))
                        ?
                    )
                ;
                builder = builder.set_last_modified(var_5);
            }
            ,
            _ => {}
        }
    }
    Ok(builder.build())
}