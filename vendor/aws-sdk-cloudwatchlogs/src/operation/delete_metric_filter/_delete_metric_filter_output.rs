// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMetricFilterOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteMetricFilterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteMetricFilterOutput {
    /// Creates a new builder-style object to manufacture [`DeleteMetricFilterOutput`](crate::operation::delete_metric_filter::DeleteMetricFilterOutput).
    pub fn builder() -> crate::operation::delete_metric_filter::builders::DeleteMetricFilterOutputBuilder {
        crate::operation::delete_metric_filter::builders::DeleteMetricFilterOutputBuilder::default()
    }
}

/// A builder for [`DeleteMetricFilterOutput`](crate::operation::delete_metric_filter::DeleteMetricFilterOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteMetricFilterOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteMetricFilterOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteMetricFilterOutput`](crate::operation::delete_metric_filter::DeleteMetricFilterOutput).
    pub fn build(self) -> crate::operation::delete_metric_filter::DeleteMetricFilterOutput {
        crate::operation::delete_metric_filter::DeleteMetricFilterOutput {
            _request_id: self._request_id,
        }
    }
}