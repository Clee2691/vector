// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMetricStreamOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteMetricStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteMetricStreamOutput {
    /// Creates a new builder-style object to manufacture [`DeleteMetricStreamOutput`](crate::operation::delete_metric_stream::DeleteMetricStreamOutput).
    pub fn builder() -> crate::operation::delete_metric_stream::builders::DeleteMetricStreamOutputBuilder {
        crate::operation::delete_metric_stream::builders::DeleteMetricStreamOutputBuilder::default()
    }
}

/// A builder for [`DeleteMetricStreamOutput`](crate::operation::delete_metric_stream::DeleteMetricStreamOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteMetricStreamOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteMetricStreamOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteMetricStreamOutput`](crate::operation::delete_metric_stream::DeleteMetricStreamOutput).
    pub fn build(self) -> crate::operation::delete_metric_stream::DeleteMetricStreamOutput {
        crate::operation::delete_metric_stream::DeleteMetricStreamOutput {
            _request_id: self._request_id,
        }
    }
}