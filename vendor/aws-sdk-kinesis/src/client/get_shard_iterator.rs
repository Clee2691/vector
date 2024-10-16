// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetShardIterator`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`stream_name(impl Into<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::stream_name) / [`set_stream_name(Option<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::set_stream_name):<br>required: **false**<br><p>The name of the Amazon Kinesis data stream.</p><br>
    ///   - [`shard_id(impl Into<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::shard_id) / [`set_shard_id(Option<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::set_shard_id):<br>required: **true**<br><p>The shard ID of the Kinesis Data Streams shard to get the iterator for.</p><br>
    ///   - [`shard_iterator_type(ShardIteratorType)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::shard_iterator_type) / [`set_shard_iterator_type(Option<ShardIteratorType>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::set_shard_iterator_type):<br>required: **true**<br><p>Determines how the shard iterator is used to start reading data records from the shard.</p>  <p>The following are the valid Amazon Kinesis shard iterator types:</p>  <ul>   <li> <p>AT_SEQUENCE_NUMBER - Start reading from the position denoted by a specific sequence number, provided in the value <code>StartingSequenceNumber</code>.</p> </li>   <li> <p>AFTER_SEQUENCE_NUMBER - Start reading right after the position denoted by a specific sequence number, provided in the value <code>StartingSequenceNumber</code>.</p> </li>   <li> <p>AT_TIMESTAMP - Start reading from the position denoted by a specific time stamp, provided in the value <code>Timestamp</code>.</p> </li>   <li> <p>TRIM_HORIZON - Start reading at the last untrimmed record in the shard in the system, which is the oldest data record in the shard.</p> </li>   <li> <p>LATEST - Start reading just after the most recent record in the shard, so that you always read the most recent data in the shard.</p> </li>  </ul><br>
    ///   - [`starting_sequence_number(impl Into<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::starting_sequence_number) / [`set_starting_sequence_number(Option<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::set_starting_sequence_number):<br>required: **false**<br><p>The sequence number of the data record in the shard from which to start reading. Used with shard iterator type AT_SEQUENCE_NUMBER and AFTER_SEQUENCE_NUMBER.</p><br>
    ///   - [`timestamp(DateTime)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::timestamp) / [`set_timestamp(Option<DateTime>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::set_timestamp):<br>required: **false**<br><p>The time stamp of the data record from which to start reading. Used with shard iterator type AT_TIMESTAMP. A time stamp is the Unix epoch date with precision in milliseconds. For example, <code>2016-04-04T19:58:46.480-00:00</code> or <code>1459799926.480</code>. If a record with this exact time stamp does not exist, the iterator returned is for the next (later) record. If the time stamp is older than the current trim horizon, the iterator returned is for the oldest untrimmed data record (TRIM_HORIZON).</p><br>
    ///   - [`stream_arn(impl Into<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::stream_arn) / [`set_stream_arn(Option<String>)`](crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::set_stream_arn):<br>required: **false**<br><p>The ARN of the stream.</p><br>
    /// - On success, responds with [`GetShardIteratorOutput`](crate::operation::get_shard_iterator::GetShardIteratorOutput) with field(s):
    ///   - [`shard_iterator(Option<String>)`](crate::operation::get_shard_iterator::GetShardIteratorOutput::shard_iterator): <p>The position in the shard from which to start reading data records sequentially. A shard iterator specifies this position using the sequence number of a data record in a shard.</p>
    /// - On failure, responds with [`SdkError<GetShardIteratorError>`](crate::operation::get_shard_iterator::GetShardIteratorError)
    pub fn get_shard_iterator(&self) -> crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder {
        crate::operation::get_shard_iterator::builders::GetShardIteratorFluentBuilder::new(self.handle.clone())
    }
}