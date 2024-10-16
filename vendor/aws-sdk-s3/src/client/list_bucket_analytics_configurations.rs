// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListBucketAnalyticsConfigurations`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket from which analytics configurations are retrieved.</p><br>
    ///   - [`continuation_token(impl Into<String>)`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::continuation_token) / [`set_continuation_token(Option<String>)`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::set_continuation_token):<br>required: **false**<br><p>The <code>ContinuationToken</code> that represents a placeholder from where this request should begin.</p><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><br>
    /// - On success, responds with [`ListBucketAnalyticsConfigurationsOutput`](crate::operation::list_bucket_analytics_configurations::ListBucketAnalyticsConfigurationsOutput) with field(s):
    ///   - [`is_truncated(Option<bool>)`](crate::operation::list_bucket_analytics_configurations::ListBucketAnalyticsConfigurationsOutput::is_truncated): <p>Indicates whether the returned list of analytics configurations is complete. A value of true indicates that the list is not complete and the NextContinuationToken will be provided for a subsequent request.</p>
    ///   - [`continuation_token(Option<String>)`](crate::operation::list_bucket_analytics_configurations::ListBucketAnalyticsConfigurationsOutput::continuation_token): <p>The marker that is used as a starting point for this analytics configuration list response. This value is present if it was sent in the request.</p>
    ///   - [`next_continuation_token(Option<String>)`](crate::operation::list_bucket_analytics_configurations::ListBucketAnalyticsConfigurationsOutput::next_continuation_token): <p> <code>NextContinuationToken</code> is sent when <code>isTruncated</code> is true, which indicates that there are more analytics configurations to list. The next request must include this <code>NextContinuationToken</code>. The token is obfuscated and is not a usable value.</p>
    ///   - [`analytics_configuration_list(Option<Vec::<AnalyticsConfiguration>>)`](crate::operation::list_bucket_analytics_configurations::ListBucketAnalyticsConfigurationsOutput::analytics_configuration_list): <p>The list of analytics configurations for a bucket.</p>
    /// - On failure, responds with [`SdkError<ListBucketAnalyticsConfigurationsError>`](crate::operation::list_bucket_analytics_configurations::ListBucketAnalyticsConfigurationsError)
    pub fn list_bucket_analytics_configurations(
        &self,
    ) -> crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder {
        crate::operation::list_bucket_analytics_configurations::builders::ListBucketAnalyticsConfigurationsFluentBuilder::new(self.handle.clone())
    }
}