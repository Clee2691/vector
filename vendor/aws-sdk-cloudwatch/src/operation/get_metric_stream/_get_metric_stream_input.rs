// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMetricStreamInput {
    /// <p>The name of the metric stream to retrieve information about.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl GetMetricStreamInput {
    /// <p>The name of the metric stream to retrieve information about.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl GetMetricStreamInput {
    /// Creates a new builder-style object to manufacture [`GetMetricStreamInput`](crate::operation::get_metric_stream::GetMetricStreamInput).
    pub fn builder() -> crate::operation::get_metric_stream::builders::GetMetricStreamInputBuilder {
        crate::operation::get_metric_stream::builders::GetMetricStreamInputBuilder::default()
    }
}

/// A builder for [`GetMetricStreamInput`](crate::operation::get_metric_stream::GetMetricStreamInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetMetricStreamInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl GetMetricStreamInputBuilder {
    /// <p>The name of the metric stream to retrieve information about.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the metric stream to retrieve information about.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the metric stream to retrieve information about.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`GetMetricStreamInput`](crate::operation::get_metric_stream::GetMetricStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_metric_stream::GetMetricStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_metric_stream::GetMetricStreamInput { name: self.name })
    }
}