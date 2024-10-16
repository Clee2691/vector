// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::merge_shards::_merge_shards_output::MergeShardsOutputBuilder;

pub use crate::operation::merge_shards::_merge_shards_input::MergeShardsInputBuilder;

impl MergeShardsInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::merge_shards::MergeShardsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::merge_shards::MergeShardsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.merge_shards();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `MergeShards`.
///
/// <p>Merges two adjacent shards in a Kinesis data stream and combines them into a single shard to reduce the stream's capacity to ingest and transport data. This API is only supported for the data streams with the provisioned capacity mode. Two shards are considered adjacent if the union of the hash key ranges for the two shards form a contiguous set with no gaps. For example, if you have two shards, one with a hash key range of 276...381 and the other with a hash key range of 382...454, then you could merge these two shards into a single shard that would have a hash key range of 276...454. After the merge, the single child shard receives data for all hash key values covered by the two parent shards.</p> <note>
/// <p>When invoking this API, you must use either the <code>StreamARN</code> or the <code>StreamName</code> parameter, or both. It is recommended that you use the <code>StreamARN</code> input parameter when you invoke this API.</p>
/// </note>
/// <p> <code>MergeShards</code> is called when there is a need to reduce the overall capacity of a stream because of excess capacity that is not being used. You must specify the shard to be merged and the adjacent shard for a stream. For more information about merging shards, see <a href="https://docs.aws.amazon.com/kinesis/latest/dev/kinesis-using-sdk-java-resharding-merge.html">Merge Two Shards</a> in the <i>Amazon Kinesis Data Streams Developer Guide</i>.</p>
/// <p>If the stream is in the <code>ACTIVE</code> state, you can call <code>MergeShards</code>. If a stream is in the <code>CREATING</code>, <code>UPDATING</code>, or <code>DELETING</code> state, <code>MergeShards</code> returns a <code>ResourceInUseException</code>. If the specified stream does not exist, <code>MergeShards</code> returns a <code>ResourceNotFoundException</code>. </p>
/// <p>You can use <code>DescribeStreamSummary</code> to check the state of the stream, which is returned in <code>StreamStatus</code>.</p>
/// <p> <code>MergeShards</code> is an asynchronous operation. Upon receiving a <code>MergeShards</code> request, Amazon Kinesis Data Streams immediately returns a response and sets the <code>StreamStatus</code> to <code>UPDATING</code>. After the operation is completed, Kinesis Data Streams sets the <code>StreamStatus</code> to <code>ACTIVE</code>. Read and write operations continue to work while the stream is in the <code>UPDATING</code> state. </p>
/// <p>You use <code>DescribeStreamSummary</code> and the <code>ListShards</code> APIs to determine the shard IDs that are specified in the <code>MergeShards</code> request. </p>
/// <p>If you try to operate on too many streams in parallel using <code>CreateStream</code>, <code>DeleteStream</code>, <code>MergeShards</code>, or <code>SplitShard</code>, you receive a <code>LimitExceededException</code>. </p>
/// <p> <code>MergeShards</code> has a limit of five transactions per second per account.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct MergeShardsFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::merge_shards::builders::MergeShardsInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::merge_shards::MergeShardsOutput,
        crate::operation::merge_shards::MergeShardsError,
    > for MergeShardsFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::merge_shards::MergeShardsOutput,
            crate::operation::merge_shards::MergeShardsError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl MergeShardsFluentBuilder {
    /// Creates a new `MergeShards`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the MergeShards as a reference.
    pub fn as_input(&self) -> &crate::operation::merge_shards::builders::MergeShardsInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::merge_shards::MergeShardsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::merge_shards::MergeShardsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::merge_shards::MergeShards::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::merge_shards::MergeShards::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::merge_shards::MergeShardsOutput,
        crate::operation::merge_shards::MergeShardsError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl Into<crate::config::Builder>) -> Self {
        self.set_config_override(Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The name of the stream for the merge.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.stream_name(input.into());
        self
    }
    /// <p>The name of the stream for the merge.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_stream_name(input);
        self
    }
    /// <p>The name of the stream for the merge.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_stream_name()
    }
    /// <p>The shard ID of the shard to combine with the adjacent shard for the merge.</p>
    pub fn shard_to_merge(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.shard_to_merge(input.into());
        self
    }
    /// <p>The shard ID of the shard to combine with the adjacent shard for the merge.</p>
    pub fn set_shard_to_merge(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_shard_to_merge(input);
        self
    }
    /// <p>The shard ID of the shard to combine with the adjacent shard for the merge.</p>
    pub fn get_shard_to_merge(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_shard_to_merge()
    }
    /// <p>The shard ID of the adjacent shard for the merge.</p>
    pub fn adjacent_shard_to_merge(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.adjacent_shard_to_merge(input.into());
        self
    }
    /// <p>The shard ID of the adjacent shard for the merge.</p>
    pub fn set_adjacent_shard_to_merge(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_adjacent_shard_to_merge(input);
        self
    }
    /// <p>The shard ID of the adjacent shard for the merge.</p>
    pub fn get_adjacent_shard_to_merge(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_adjacent_shard_to_merge()
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.stream_arn(input.into());
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_stream_arn(input);
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_stream_arn()
    }
}