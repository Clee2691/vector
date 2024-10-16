// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListQueues`](crate::operation::list_queues::builders::ListQueuesFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`queue_name_prefix(impl Into<String>)`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::queue_name_prefix) / [`set_queue_name_prefix(Option<String>)`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::set_queue_name_prefix):<br>required: **false**<br><p>A string to use for filtering the list results. Only those queues whose name begins with the specified string are returned.</p>  <p>Queue URLs and names are case-sensitive.</p><br>
    ///   - [`next_token(impl Into<String>)`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::set_next_token):<br>required: **false**<br><p>Pagination token to request the next set of results.</p><br>
    ///   - [`max_results(i32)`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::max_results) / [`set_max_results(Option<i32>)`](crate::operation::list_queues::builders::ListQueuesFluentBuilder::set_max_results):<br>required: **false**<br><p>Maximum number of results to include in the response. Value range is 1 to 1000. You must set <code>MaxResults</code> to receive a value for <code>NextToken</code> in the response.</p><br>
    /// - On success, responds with [`ListQueuesOutput`](crate::operation::list_queues::ListQueuesOutput) with field(s):
    ///   - [`queue_urls(Option<Vec::<String>>)`](crate::operation::list_queues::ListQueuesOutput::queue_urls): <p>A list of queue URLs, up to 1,000 entries, or the value of <code>MaxResults</code> that you sent in the request.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::list_queues::ListQueuesOutput::next_token): <p>Pagination token to include in the next request. Token value is <code>null</code> if there are no additional results to request, or if you did not set <code>MaxResults</code> in the request.</p>
    /// - On failure, responds with [`SdkError<ListQueuesError>`](crate::operation::list_queues::ListQueuesError)
    pub fn list_queues(&self) -> crate::operation::list_queues::builders::ListQueuesFluentBuilder {
        crate::operation::list_queues::builders::ListQueuesFluentBuilder::new(self.handle.clone())
    }
}