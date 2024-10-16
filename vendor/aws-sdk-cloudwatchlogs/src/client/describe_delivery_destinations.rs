// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`DescribeDeliveryDestinations`](crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`next_token(impl Into<String>)`](crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder::set_next_token):<br>required: **false**<br><p>The token for the next set of items to return. The token expires after 24 hours.</p><br>
    ///   - [`limit(i32)`](crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder::limit) / [`set_limit(Option<i32>)`](crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder::set_limit):<br>required: **false**<br><p>Optionally specify the maximum number of delivery destinations to return in the response.</p><br>
    /// - On success, responds with [`DescribeDeliveryDestinationsOutput`](crate::operation::describe_delivery_destinations::DescribeDeliveryDestinationsOutput) with field(s):
    ///   - [`delivery_destinations(Option<Vec::<DeliveryDestination>>)`](crate::operation::describe_delivery_destinations::DescribeDeliveryDestinationsOutput::delivery_destinations): <p>An array of structures. Each structure contains information about one delivery destination in the account.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::describe_delivery_destinations::DescribeDeliveryDestinationsOutput::next_token): <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    /// - On failure, responds with [`SdkError<DescribeDeliveryDestinationsError>`](crate::operation::describe_delivery_destinations::DescribeDeliveryDestinationsError)
    pub fn describe_delivery_destinations(
        &self,
    ) -> crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder {
        crate::operation::describe_delivery_destinations::builders::DescribeDeliveryDestinationsFluentBuilder::new(self.handle.clone())
    }
}