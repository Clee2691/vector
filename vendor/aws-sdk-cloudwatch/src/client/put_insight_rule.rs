// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`PutInsightRule`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`rule_name(impl Into<String>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::rule_name) / [`set_rule_name(Option<String>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::set_rule_name):<br>required: **true**<br><p>A unique name for the rule.</p><br>
    ///   - [`rule_state(impl Into<String>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::rule_state) / [`set_rule_state(Option<String>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::set_rule_state):<br>required: **false**<br><p>The state of the rule. Valid values are ENABLED and DISABLED.</p><br>
    ///   - [`rule_definition(impl Into<String>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::rule_definition) / [`set_rule_definition(Option<String>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::set_rule_definition):<br>required: **true**<br><p>The definition of the rule, as a JSON object. For details on the valid syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html">Contributor Insights Rule Syntax</a>.</p><br>
    ///   - [`tags(Tag)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::tags) / [`set_tags(Option<Vec::<Tag>>)`](crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::set_tags):<br>required: **false**<br><p>A list of key-value pairs to associate with the Contributor Insights rule. You can associate as many as 50 tags with a rule.</p>  <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions, by granting a user permission to access or change only the resources that have certain tag values.</p>  <p>To be able to associate tags with a rule, you must have the <code>cloudwatch:TagResource</code> permission in addition to the <code>cloudwatch:PutInsightRule</code> permission.</p>  <p>If you are using this operation to update an existing Contributor Insights rule, any tags you specify in this parameter are ignored. To change the tags of an existing rule, use <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_TagResource.html">TagResource</a>.</p><br>
    /// - On success, responds with [`PutInsightRuleOutput`](crate::operation::put_insight_rule::PutInsightRuleOutput)
    /// - On failure, responds with [`SdkError<PutInsightRuleError>`](crate::operation::put_insight_rule::PutInsightRuleError)
    pub fn put_insight_rule(&self) -> crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder {
        crate::operation::put_insight_rule::builders::PutInsightRuleFluentBuilder::new(self.handle.clone())
    }
}