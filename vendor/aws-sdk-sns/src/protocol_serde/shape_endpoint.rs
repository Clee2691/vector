// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::needless_question_mark)]
pub fn de_endpoint(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::Endpoint, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::Endpoint::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("EndpointArn") /* EndpointArn com.amazonaws.sns#Endpoint$EndpointArn */ =>  {
                let var_1 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_endpoint_arn(var_1);
            }
            ,
            s if s.matches("Attributes") /* Attributes com.amazonaws.sns#Endpoint$Attributes */ =>  {
                let var_2 =
                    Some(
                        crate::protocol_serde::shape_map_string_to_string::de_map_string_to_string(&mut tag)
                        ?
                    )
                ;
                builder = builder.set_attributes(var_2);
            }
            ,
            _ => {}
        }
    }
    Ok(builder.build())
}