// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output for <code>PutRecords</code>.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRecordsRequestEntry {
    /// <p>The data blob to put into the record, which is base64-encoded when the blob is serialized. When the data blob (the payload before base64-encoding) is added to the partition key size, the total size must not exceed the maximum record size (1 MiB).</p>
    pub data: ::aws_smithy_types::Blob,
    /// <p>The hash value used to determine explicitly the shard that the data record is assigned to by overriding the partition key hash.</p>
    pub explicit_hash_key: ::std::option::Option<::std::string::String>,
    /// <p>Determines which shard in the stream the data record is assigned to. Partition keys are Unicode strings with a maximum length limit of 256 characters for each key. Amazon Kinesis Data Streams uses the partition key as input to a hash function that maps the partition key and associated data to a specific shard. Specifically, an MD5 hash function is used to map partition keys to 128-bit integer values and to map associated data records to shards. As a result of this hashing mechanism, all data records with the same partition key map to the same shard within the stream.</p>
    pub partition_key: ::std::string::String,
}
impl PutRecordsRequestEntry {
    /// <p>The data blob to put into the record, which is base64-encoded when the blob is serialized. When the data blob (the payload before base64-encoding) is added to the partition key size, the total size must not exceed the maximum record size (1 MiB).</p>
    pub fn data(&self) -> &::aws_smithy_types::Blob {
        &self.data
    }
    /// <p>The hash value used to determine explicitly the shard that the data record is assigned to by overriding the partition key hash.</p>
    pub fn explicit_hash_key(&self) -> ::std::option::Option<&str> {
        self.explicit_hash_key.as_deref()
    }
    /// <p>Determines which shard in the stream the data record is assigned to. Partition keys are Unicode strings with a maximum length limit of 256 characters for each key. Amazon Kinesis Data Streams uses the partition key as input to a hash function that maps the partition key and associated data to a specific shard. Specifically, an MD5 hash function is used to map partition keys to 128-bit integer values and to map associated data records to shards. As a result of this hashing mechanism, all data records with the same partition key map to the same shard within the stream.</p>
    pub fn partition_key(&self) -> &str {
        use std::ops::Deref;
        self.partition_key.deref()
    }
}
impl PutRecordsRequestEntry {
    /// Creates a new builder-style object to manufacture [`PutRecordsRequestEntry`](crate::types::PutRecordsRequestEntry).
    pub fn builder() -> crate::types::builders::PutRecordsRequestEntryBuilder {
        crate::types::builders::PutRecordsRequestEntryBuilder::default()
    }
}

/// A builder for [`PutRecordsRequestEntry`](crate::types::PutRecordsRequestEntry).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutRecordsRequestEntryBuilder {
    pub(crate) data: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) explicit_hash_key: ::std::option::Option<::std::string::String>,
    pub(crate) partition_key: ::std::option::Option<::std::string::String>,
}
impl PutRecordsRequestEntryBuilder {
    /// <p>The data blob to put into the record, which is base64-encoded when the blob is serialized. When the data blob (the payload before base64-encoding) is added to the partition key size, the total size must not exceed the maximum record size (1 MiB).</p>
    /// This field is required.
    pub fn data(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.data = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data blob to put into the record, which is base64-encoded when the blob is serialized. When the data blob (the payload before base64-encoding) is added to the partition key size, the total size must not exceed the maximum record size (1 MiB).</p>
    pub fn set_data(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.data = input;
        self
    }
    /// <p>The data blob to put into the record, which is base64-encoded when the blob is serialized. When the data blob (the payload before base64-encoding) is added to the partition key size, the total size must not exceed the maximum record size (1 MiB).</p>
    pub fn get_data(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.data
    }
    /// <p>The hash value used to determine explicitly the shard that the data record is assigned to by overriding the partition key hash.</p>
    pub fn explicit_hash_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.explicit_hash_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The hash value used to determine explicitly the shard that the data record is assigned to by overriding the partition key hash.</p>
    pub fn set_explicit_hash_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.explicit_hash_key = input;
        self
    }
    /// <p>The hash value used to determine explicitly the shard that the data record is assigned to by overriding the partition key hash.</p>
    pub fn get_explicit_hash_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.explicit_hash_key
    }
    /// <p>Determines which shard in the stream the data record is assigned to. Partition keys are Unicode strings with a maximum length limit of 256 characters for each key. Amazon Kinesis Data Streams uses the partition key as input to a hash function that maps the partition key and associated data to a specific shard. Specifically, an MD5 hash function is used to map partition keys to 128-bit integer values and to map associated data records to shards. As a result of this hashing mechanism, all data records with the same partition key map to the same shard within the stream.</p>
    /// This field is required.
    pub fn partition_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.partition_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Determines which shard in the stream the data record is assigned to. Partition keys are Unicode strings with a maximum length limit of 256 characters for each key. Amazon Kinesis Data Streams uses the partition key as input to a hash function that maps the partition key and associated data to a specific shard. Specifically, an MD5 hash function is used to map partition keys to 128-bit integer values and to map associated data records to shards. As a result of this hashing mechanism, all data records with the same partition key map to the same shard within the stream.</p>
    pub fn set_partition_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.partition_key = input;
        self
    }
    /// <p>Determines which shard in the stream the data record is assigned to. Partition keys are Unicode strings with a maximum length limit of 256 characters for each key. Amazon Kinesis Data Streams uses the partition key as input to a hash function that maps the partition key and associated data to a specific shard. Specifically, an MD5 hash function is used to map partition keys to 128-bit integer values and to map associated data records to shards. As a result of this hashing mechanism, all data records with the same partition key map to the same shard within the stream.</p>
    pub fn get_partition_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.partition_key
    }
    /// Consumes the builder and constructs a [`PutRecordsRequestEntry`](crate::types::PutRecordsRequestEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`data`](crate::types::builders::PutRecordsRequestEntryBuilder::data)
    /// - [`partition_key`](crate::types::builders::PutRecordsRequestEntryBuilder::partition_key)
    pub fn build(self) -> ::std::result::Result<crate::types::PutRecordsRequestEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PutRecordsRequestEntry {
            data: self.data.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data",
                    "data was not specified but it is required when building PutRecordsRequestEntry",
                )
            })?,
            explicit_hash_key: self.explicit_hash_key,
            partition_key: self.partition_key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "partition_key",
                    "partition_key was not specified but it is required when building PutRecordsRequestEntry",
                )
            })?,
        })
    }
}