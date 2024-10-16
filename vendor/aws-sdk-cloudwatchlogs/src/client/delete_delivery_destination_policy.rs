// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`DeleteDeliveryDestinationPolicy`](crate::operation::delete_delivery_destination_policy::builders::DeleteDeliveryDestinationPolicyFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`delivery_destination_name(impl Into<String>)`](crate::operation::delete_delivery_destination_policy::builders::DeleteDeliveryDestinationPolicyFluentBuilder::delivery_destination_name) / [`set_delivery_destination_name(Option<String>)`](crate::operation::delete_delivery_destination_policy::builders::DeleteDeliveryDestinationPolicyFluentBuilder::set_delivery_destination_name):<br>required: **true**<br><p>The name of the delivery destination that you want to delete the policy for.</p><br>
    /// - On success, responds with [`DeleteDeliveryDestinationPolicyOutput`](crate::operation::delete_delivery_destination_policy::DeleteDeliveryDestinationPolicyOutput)
    /// - On failure, responds with [`SdkError<DeleteDeliveryDestinationPolicyError>`](crate::operation::delete_delivery_destination_policy::DeleteDeliveryDestinationPolicyError)
    pub fn delete_delivery_destination_policy(
        &self,
    ) -> crate::operation::delete_delivery_destination_policy::builders::DeleteDeliveryDestinationPolicyFluentBuilder {
        crate::operation::delete_delivery_destination_policy::builders::DeleteDeliveryDestinationPolicyFluentBuilder::new(self.handle.clone())
    }
}