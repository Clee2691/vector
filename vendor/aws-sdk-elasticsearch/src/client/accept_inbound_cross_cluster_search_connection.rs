// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`AcceptInboundCrossClusterSearchConnection`](crate::operation::accept_inbound_cross_cluster_search_connection::builders::AcceptInboundCrossClusterSearchConnectionFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`cross_cluster_search_connection_id(impl Into<String>)`](crate::operation::accept_inbound_cross_cluster_search_connection::builders::AcceptInboundCrossClusterSearchConnectionFluentBuilder::cross_cluster_search_connection_id) / [`set_cross_cluster_search_connection_id(Option<String>)`](crate::operation::accept_inbound_cross_cluster_search_connection::builders::AcceptInboundCrossClusterSearchConnectionFluentBuilder::set_cross_cluster_search_connection_id):<br>required: **true**<br><p>The id of the inbound connection that you want to accept.</p><br>
    /// - On success, responds with [`AcceptInboundCrossClusterSearchConnectionOutput`](crate::operation::accept_inbound_cross_cluster_search_connection::AcceptInboundCrossClusterSearchConnectionOutput) with field(s):
    ///   - [`cross_cluster_search_connection(Option<InboundCrossClusterSearchConnection>)`](crate::operation::accept_inbound_cross_cluster_search_connection::AcceptInboundCrossClusterSearchConnectionOutput::cross_cluster_search_connection): <p>Specifies the <code><code>InboundCrossClusterSearchConnection</code></code> of accepted inbound connection. </p>
    /// - On failure, responds with [`SdkError<AcceptInboundCrossClusterSearchConnectionError>`](crate::operation::accept_inbound_cross_cluster_search_connection::AcceptInboundCrossClusterSearchConnectionError)
    pub fn accept_inbound_cross_cluster_search_connection(
        &self,
    ) -> crate::operation::accept_inbound_cross_cluster_search_connection::builders::AcceptInboundCrossClusterSearchConnectionFluentBuilder {
        crate::operation::accept_inbound_cross_cluster_search_connection::builders::AcceptInboundCrossClusterSearchConnectionFluentBuilder::new(
            self.handle.clone(),
        )
    }
}