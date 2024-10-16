// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`UpdateElasticsearchDomainConfig`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`domain_name(impl Into<String>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::domain_name) / [`set_domain_name(Option<String>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_domain_name):<br>required: **true**<br><p>The name of the Elasticsearch domain that you are updating. </p><br>
    ///   - [`elasticsearch_cluster_config(ElasticsearchClusterConfig)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::elasticsearch_cluster_config) / [`set_elasticsearch_cluster_config(Option<ElasticsearchClusterConfig>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_elasticsearch_cluster_config):<br>required: **false**<br><p>The type and number of instances to instantiate for the domain cluster.</p><br>
    ///   - [`ebs_options(EbsOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::ebs_options) / [`set_ebs_options(Option<EbsOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_ebs_options):<br>required: **false**<br><p>Specify the type and size of the EBS volume that you want to use. </p><br>
    ///   - [`snapshot_options(SnapshotOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::snapshot_options) / [`set_snapshot_options(Option<SnapshotOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_snapshot_options):<br>required: **false**<br><p>Option to set the time, in UTC format, for the daily automated snapshot. Default value is <code>0</code> hours. </p><br>
    ///   - [`vpc_options(VpcOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::vpc_options) / [`set_vpc_options(Option<VpcOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_vpc_options):<br>required: **false**<br><p>Options to specify the subnets and security groups for VPC endpoint. For more information, see <a href="http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html#es-creating-vpc" target="_blank">Creating a VPC</a> in <i>VPC Endpoints for Amazon Elasticsearch Service Domains</i></p><br>
    ///   - [`cognito_options(CognitoOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::cognito_options) / [`set_cognito_options(Option<CognitoOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_cognito_options):<br>required: **false**<br><p>Options to specify the Cognito user and identity pools for Kibana authentication. For more information, see <a href="http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html" target="_blank">Amazon Cognito Authentication for Kibana</a>.</p><br>
    ///   - [`advanced_options(impl Into<String>, impl Into<String>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::advanced_options) / [`set_advanced_options(Option<HashMap::<String, String>>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_advanced_options):<br>required: **false**<br><p>Modifies the advanced option to allow references to indices in an HTTP request body. Must be <code>false</code> when configuring access to individual sub-resources. By default, the value is <code>true</code>. See <a href="http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-advanced-options" target="_blank">Configuration Advanced Options</a> for more information.</p><br>
    ///   - [`access_policies(impl Into<String>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::access_policies) / [`set_access_policies(Option<String>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_access_policies):<br>required: **false**<br><p>IAM access policy as a JSON-formatted string.</p><br>
    ///   - [`log_publishing_options(LogType, LogPublishingOption)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::log_publishing_options) / [`set_log_publishing_options(Option<HashMap::<LogType, LogPublishingOption>>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_log_publishing_options):<br>required: **false**<br><p>Map of <code>LogType</code> and <code>LogPublishingOption</code>, each containing options to publish a given type of Elasticsearch log.</p><br>
    ///   - [`domain_endpoint_options(DomainEndpointOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::domain_endpoint_options) / [`set_domain_endpoint_options(Option<DomainEndpointOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_domain_endpoint_options):<br>required: **false**<br><p>Options to specify configuration that will be applied to the domain endpoint.</p><br>
    ///   - [`advanced_security_options(AdvancedSecurityOptionsInput)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::advanced_security_options) / [`set_advanced_security_options(Option<AdvancedSecurityOptionsInput>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_advanced_security_options):<br>required: **false**<br><p>Specifies advanced security options.</p><br>
    ///   - [`node_to_node_encryption_options(NodeToNodeEncryptionOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::node_to_node_encryption_options) / [`set_node_to_node_encryption_options(Option<NodeToNodeEncryptionOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_node_to_node_encryption_options):<br>required: **false**<br><p>Specifies the NodeToNodeEncryptionOptions.</p><br>
    ///   - [`encryption_at_rest_options(EncryptionAtRestOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::encryption_at_rest_options) / [`set_encryption_at_rest_options(Option<EncryptionAtRestOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_encryption_at_rest_options):<br>required: **false**<br><p>Specifies the Encryption At Rest Options.</p><br>
    ///   - [`auto_tune_options(AutoTuneOptions)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::auto_tune_options) / [`set_auto_tune_options(Option<AutoTuneOptions>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_auto_tune_options):<br>required: **false**<br><p>Specifies Auto-Tune options.</p><br>
    ///   - [`dry_run(bool)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::dry_run) / [`set_dry_run(Option<bool>)`](crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::set_dry_run):<br>required: **false**<br><p> This flag, when set to True, specifies whether the <code>UpdateElasticsearchDomain</code> request should return the results of validation checks without actually applying the change. This flag, when set to True, specifies the deployment mechanism through which the update shall be applied on the domain. This will not actually perform the Update. </p><br>
    /// - On success, responds with [`UpdateElasticsearchDomainConfigOutput`](crate::operation::update_elasticsearch_domain_config::UpdateElasticsearchDomainConfigOutput) with field(s):
    ///   - [`domain_config(Option<ElasticsearchDomainConfig>)`](crate::operation::update_elasticsearch_domain_config::UpdateElasticsearchDomainConfigOutput::domain_config): <p>The status of the updated Elasticsearch domain. </p>
    ///   - [`dry_run_results(Option<DryRunResults>)`](crate::operation::update_elasticsearch_domain_config::UpdateElasticsearchDomainConfigOutput::dry_run_results): <p>Contains result of DryRun. </p>
    /// - On failure, responds with [`SdkError<UpdateElasticsearchDomainConfigError>`](crate::operation::update_elasticsearch_domain_config::UpdateElasticsearchDomainConfigError)
    pub fn update_elasticsearch_domain_config(
        &self,
    ) -> crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder {
        crate::operation::update_elasticsearch_domain_config::builders::UpdateElasticsearchDomainConfigFluentBuilder::new(self.handle.clone())
    }
}