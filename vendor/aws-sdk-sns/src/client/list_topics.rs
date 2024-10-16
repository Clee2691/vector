// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListTopics`](crate::operation::list_topics::builders::ListTopicsFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::list_topics::builders::ListTopicsFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`next_token(impl Into<String>)`](crate::operation::list_topics::builders::ListTopicsFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::list_topics::builders::ListTopicsFluentBuilder::set_next_token):<br>required: **false**<br><p>Token returned by the previous <code>ListTopics</code> request.</p><br>
    /// - On success, responds with [`ListTopicsOutput`](crate::operation::list_topics::ListTopicsOutput) with field(s):
    ///   - [`topics(Option<Vec::<Topic>>)`](crate::operation::list_topics::ListTopicsOutput::topics): <p>A list of topic ARNs.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::list_topics::ListTopicsOutput::next_token): <p>Token to pass along to the next <code>ListTopics</code> request. This element is returned if there are additional topics to retrieve.</p>
    /// - On failure, responds with [`SdkError<ListTopicsError>`](crate::operation::list_topics::ListTopicsError)
    pub fn list_topics(&self) -> crate::operation::list_topics::builders::ListTopicsFluentBuilder {
        crate::operation::list_topics::builders::ListTopicsFluentBuilder::new(self.handle.clone())
    }
}