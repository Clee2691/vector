// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutInsightRuleOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutInsightRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutInsightRuleOutput {
    /// Creates a new builder-style object to manufacture [`PutInsightRuleOutput`](crate::operation::put_insight_rule::PutInsightRuleOutput).
    pub fn builder() -> crate::operation::put_insight_rule::builders::PutInsightRuleOutputBuilder {
        crate::operation::put_insight_rule::builders::PutInsightRuleOutputBuilder::default()
    }
}

/// A builder for [`PutInsightRuleOutput`](crate::operation::put_insight_rule::PutInsightRuleOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutInsightRuleOutputBuilder {
    _request_id: Option<String>,
}
impl PutInsightRuleOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutInsightRuleOutput`](crate::operation::put_insight_rule::PutInsightRuleOutput).
    pub fn build(self) -> crate::operation::put_insight_rule::PutInsightRuleOutput {
        crate::operation::put_insight_rule::PutInsightRuleOutput {
            _request_id: self._request_id,
        }
    }
}