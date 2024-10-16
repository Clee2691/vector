// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListSubscriptions`](crate::operation::list_subscriptions::builders::ListSubscriptionsFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::list_subscriptions::builders::ListSubscriptionsFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`next_token(impl Into<String>)`](crate::operation::list_subscriptions::builders::ListSubscriptionsFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::list_subscriptions::builders::ListSubscriptionsFluentBuilder::set_next_token):<br>required: **false**<br><p>Token returned by the previous <code>ListSubscriptions</code> request.</p><br>
    /// - On success, responds with [`ListSubscriptionsOutput`](crate::operation::list_subscriptions::ListSubscriptionsOutput) with field(s):
    ///   - [`subscriptions(Option<Vec::<Subscription>>)`](crate::operation::list_subscriptions::ListSubscriptionsOutput::subscriptions): <p>A list of subscriptions.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::list_subscriptions::ListSubscriptionsOutput::next_token): <p>Token to pass along to the next <code>ListSubscriptions</code> request. This element is returned if there are more subscriptions to retrieve.</p>
    /// - On failure, responds with [`SdkError<ListSubscriptionsError>`](crate::operation::list_subscriptions::ListSubscriptionsError)
    pub fn list_subscriptions(&self) -> crate::operation::list_subscriptions::builders::ListSubscriptionsFluentBuilder {
        crate::operation::list_subscriptions::builders::ListSubscriptionsFluentBuilder::new(self.handle.clone())
    }
}