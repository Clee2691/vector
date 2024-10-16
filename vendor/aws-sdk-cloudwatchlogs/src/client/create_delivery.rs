// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`CreateDelivery`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`delivery_source_name(impl Into<String>)`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::delivery_source_name) / [`set_delivery_source_name(Option<String>)`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::set_delivery_source_name):<br>required: **true**<br><p>The name of the delivery source to use for this delivery.</p><br>
    ///   - [`delivery_destination_arn(impl Into<String>)`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::delivery_destination_arn) / [`set_delivery_destination_arn(Option<String>)`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::set_delivery_destination_arn):<br>required: **true**<br><p>The ARN of the delivery destination to use for this delivery.</p><br>
    ///   - [`tags(impl Into<String>, impl Into<String>)`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::tags) / [`set_tags(Option<HashMap::<String, String>>)`](crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::set_tags):<br>required: **false**<br><p>An optional list of key-value pairs to associate with the resource.</p>  <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p><br>
    /// - On success, responds with [`CreateDeliveryOutput`](crate::operation::create_delivery::CreateDeliveryOutput) with field(s):
    ///   - [`delivery(Option<Delivery>)`](crate::operation::create_delivery::CreateDeliveryOutput::delivery): <p>A structure that contains information about the delivery that you just created.</p>
    /// - On failure, responds with [`SdkError<CreateDeliveryError>`](crate::operation::create_delivery::CreateDeliveryError)
    pub fn create_delivery(&self) -> crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder {
        crate::operation::create_delivery::builders::CreateDeliveryFluentBuilder::new(self.handle.clone())
    }
}