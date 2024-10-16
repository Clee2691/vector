// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_get_metric_statistics_http_error(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::get_metric_statistics::GetMetricStatisticsOutput,
    crate::operation::get_metric_statistics::GetMetricStatisticsError,
> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled)?;
    generic_builder = ::aws_types::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    let error_code = match generic.code() {
        Some(code) => code,
        None => return Err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled(generic)),
    };

    let _error_message = generic.message().map(|msg| msg.to_owned());
    Err(match error_code {
        "InternalServiceError" => crate::operation::get_metric_statistics::GetMetricStatisticsError::InternalServiceFault({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::InternalServiceFaultBuilder::default();
                output = crate::protocol_serde::shape_internal_service_fault::de_internal_service_fault_xml_err(_response_body, output)
                    .map_err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "InvalidParameterCombination" => crate::operation::get_metric_statistics::GetMetricStatisticsError::InvalidParameterCombinationException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::InvalidParameterCombinationExceptionBuilder::default();
                output = crate::protocol_serde::shape_invalid_parameter_combination_exception::de_invalid_parameter_combination_exception_xml_err(
                    _response_body,
                    output,
                )
                .map_err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "InvalidParameterValue" => crate::operation::get_metric_statistics::GetMetricStatisticsError::InvalidParameterValueException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::InvalidParameterValueExceptionBuilder::default();
                output = crate::protocol_serde::shape_invalid_parameter_value_exception::de_invalid_parameter_value_exception_xml_err(
                    _response_body,
                    output,
                )
                .map_err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "MissingParameter" => crate::operation::get_metric_statistics::GetMetricStatisticsError::MissingRequiredParameterException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::MissingRequiredParameterExceptionBuilder::default();
                output = crate::protocol_serde::shape_missing_required_parameter_exception::de_missing_required_parameter_exception_xml_err(
                    _response_body,
                    output,
                )
                .map_err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        _ => crate::operation::get_metric_statistics::GetMetricStatisticsError::generic(generic),
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_get_metric_statistics_http_response(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::get_metric_statistics::GetMetricStatisticsOutput,
    crate::operation::get_metric_statistics::GetMetricStatisticsError,
> {
    Ok({
        #[allow(unused_mut)]
        let mut output = crate::operation::get_metric_statistics::builders::GetMetricStatisticsOutputBuilder::default();
        output = crate::protocol_serde::shape_get_metric_statistics::de_get_metric_statistics(_response_body, output)
            .map_err(crate::operation::get_metric_statistics::GetMetricStatisticsError::unhandled)?;
        output._set_request_id(::aws_types::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        output.build()
    })
}

#[allow(unused_mut)]
pub fn de_get_metric_statistics(
    inp: &[u8],
    mut builder: crate::operation::get_metric_statistics::builders::GetMetricStatisticsOutputBuilder,
) -> Result<crate::operation::get_metric_statistics::builders::GetMetricStatisticsOutputBuilder, ::aws_smithy_xml::decode::XmlDecodeError> {
    let mut doc = ::aws_smithy_xml::decode::Document::try_from(inp)?;

    #[allow(unused_mut)]
    let mut decoder = doc.root_element()?;
    #[allow(unused_variables)]
    let start_el = decoder.start_el();
    if !(start_el.matches("GetMetricStatisticsResponse")) {
        return Err(::aws_smithy_xml::decode::XmlDecodeError::custom(format!(
            "invalid root, expected GetMetricStatisticsResponse got {:?}",
            start_el
        )));
    }
    if let Some(mut result_tag) = decoder.next_tag() {
        let start_el = result_tag.start_el();
        if !(start_el.matches("GetMetricStatisticsResult")) {
            return Err(::aws_smithy_xml::decode::XmlDecodeError::custom(format!(
                "invalid result, expected GetMetricStatisticsResult got {:?}",
                start_el
            )));
        }
        while let Some(mut tag) = result_tag.next_tag() {
            match tag.start_el() {
            s if s.matches("Label") /* Label com.amazonaws.cloudwatch.synthetic#GetMetricStatisticsOutput$Label */ =>  {
                let var_1 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_label(var_1);
            }
            ,
            s if s.matches("Datapoints") /* Datapoints com.amazonaws.cloudwatch.synthetic#GetMetricStatisticsOutput$Datapoints */ =>  {
                let var_2 =
                    Some(
                        crate::protocol_serde::shape_datapoints::de_datapoints(&mut tag)
                        ?
                    )
                ;
                builder = builder.set_datapoints(var_2);
            }
            ,
            _ => {}
        }
        }
    } else {
        return Err(::aws_smithy_xml::decode::XmlDecodeError::custom("expected GetMetricStatisticsResult tag"));
    };
    Ok(builder)
}