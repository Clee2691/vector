// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`UntagResource`](crate::operation::untag_resource::builders::UntagResourceFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`resource_arn(impl Into<String>)`](crate::operation::untag_resource::builders::UntagResourceFluentBuilder::resource_arn) / [`set_resource_arn(Option<String>)`](crate::operation::untag_resource::builders::UntagResourceFluentBuilder::set_resource_arn):<br>required: **true**<br><p>The ARN of the CloudWatch Logs resource that you're removing tags from.</p>  <p>The ARN format of a log group is <code>arn:aws:logs:<i>Region</i>:<i>account-id</i>:log-group:<i>log-group-name</i> </code> </p>  <p>The ARN format of a destination is <code>arn:aws:logs:<i>Region</i>:<i>account-id</i>:destination:<i>destination-name</i> </code> </p>  <p>For more information about ARN format, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-access-control-overview-cwl.html">CloudWatch Logs resources and operations</a>.</p><br>
    ///   - [`tag_keys(impl Into<String>)`](crate::operation::untag_resource::builders::UntagResourceFluentBuilder::tag_keys) / [`set_tag_keys(Option<Vec::<String>>)`](crate::operation::untag_resource::builders::UntagResourceFluentBuilder::set_tag_keys):<br>required: **true**<br><p>The list of tag keys to remove from the resource.</p><br>
    /// - On success, responds with [`UntagResourceOutput`](crate::operation::untag_resource::UntagResourceOutput)
    /// - On failure, responds with [`SdkError<UntagResourceError>`](crate::operation::untag_resource::UntagResourceError)
    pub fn untag_resource(&self) -> crate::operation::untag_resource::builders::UntagResourceFluentBuilder {
        crate::operation::untag_resource::builders::UntagResourceFluentBuilder::new(self.handle.clone())
    }
}