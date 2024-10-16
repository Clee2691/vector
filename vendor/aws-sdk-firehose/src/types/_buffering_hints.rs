// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes hints for the buffering to perform before delivering data to the destination. These options are treated as hints, and therefore Kinesis Data Firehose might choose to use different values when it is optimal. The <code>SizeInMBs</code> and <code>IntervalInSeconds</code> parameters are optional. However, if specify a value for one of them, you must also provide a value for the other.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BufferingHints {
    /// <p>Buffer incoming data to the specified size, in MiBs, before delivering it to the destination. The default value is 5. This parameter is optional but if you specify a value for it, you must also specify a value for <code>IntervalInSeconds</code>, and vice versa.</p>
    /// <p>We recommend setting this parameter to a value greater than the amount of data you typically ingest into the delivery stream in 10 seconds. For example, if you typically ingest data at 1 MiB/sec, the value should be 10 MiB or higher.</p>
    pub size_in_mbs: ::std::option::Option<i32>,
    /// <p>Buffer incoming data for the specified period of time, in seconds, before delivering it to the destination. The default value is 300. This parameter is optional but if you specify a value for it, you must also specify a value for <code>SizeInMBs</code>, and vice versa.</p>
    pub interval_in_seconds: ::std::option::Option<i32>,
}
impl BufferingHints {
    /// <p>Buffer incoming data to the specified size, in MiBs, before delivering it to the destination. The default value is 5. This parameter is optional but if you specify a value for it, you must also specify a value for <code>IntervalInSeconds</code>, and vice versa.</p>
    /// <p>We recommend setting this parameter to a value greater than the amount of data you typically ingest into the delivery stream in 10 seconds. For example, if you typically ingest data at 1 MiB/sec, the value should be 10 MiB or higher.</p>
    pub fn size_in_mbs(&self) -> ::std::option::Option<i32> {
        self.size_in_mbs
    }
    /// <p>Buffer incoming data for the specified period of time, in seconds, before delivering it to the destination. The default value is 300. This parameter is optional but if you specify a value for it, you must also specify a value for <code>SizeInMBs</code>, and vice versa.</p>
    pub fn interval_in_seconds(&self) -> ::std::option::Option<i32> {
        self.interval_in_seconds
    }
}
impl BufferingHints {
    /// Creates a new builder-style object to manufacture [`BufferingHints`](crate::types::BufferingHints).
    pub fn builder() -> crate::types::builders::BufferingHintsBuilder {
        crate::types::builders::BufferingHintsBuilder::default()
    }
}

/// A builder for [`BufferingHints`](crate::types::BufferingHints).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct BufferingHintsBuilder {
    pub(crate) size_in_mbs: ::std::option::Option<i32>,
    pub(crate) interval_in_seconds: ::std::option::Option<i32>,
}
impl BufferingHintsBuilder {
    /// <p>Buffer incoming data to the specified size, in MiBs, before delivering it to the destination. The default value is 5. This parameter is optional but if you specify a value for it, you must also specify a value for <code>IntervalInSeconds</code>, and vice versa.</p>
    /// <p>We recommend setting this parameter to a value greater than the amount of data you typically ingest into the delivery stream in 10 seconds. For example, if you typically ingest data at 1 MiB/sec, the value should be 10 MiB or higher.</p>
    pub fn size_in_mbs(mut self, input: i32) -> Self {
        self.size_in_mbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Buffer incoming data to the specified size, in MiBs, before delivering it to the destination. The default value is 5. This parameter is optional but if you specify a value for it, you must also specify a value for <code>IntervalInSeconds</code>, and vice versa.</p>
    /// <p>We recommend setting this parameter to a value greater than the amount of data you typically ingest into the delivery stream in 10 seconds. For example, if you typically ingest data at 1 MiB/sec, the value should be 10 MiB or higher.</p>
    pub fn set_size_in_mbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_in_mbs = input;
        self
    }
    /// <p>Buffer incoming data to the specified size, in MiBs, before delivering it to the destination. The default value is 5. This parameter is optional but if you specify a value for it, you must also specify a value for <code>IntervalInSeconds</code>, and vice versa.</p>
    /// <p>We recommend setting this parameter to a value greater than the amount of data you typically ingest into the delivery stream in 10 seconds. For example, if you typically ingest data at 1 MiB/sec, the value should be 10 MiB or higher.</p>
    pub fn get_size_in_mbs(&self) -> &::std::option::Option<i32> {
        &self.size_in_mbs
    }
    /// <p>Buffer incoming data for the specified period of time, in seconds, before delivering it to the destination. The default value is 300. This parameter is optional but if you specify a value for it, you must also specify a value for <code>SizeInMBs</code>, and vice versa.</p>
    pub fn interval_in_seconds(mut self, input: i32) -> Self {
        self.interval_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>Buffer incoming data for the specified period of time, in seconds, before delivering it to the destination. The default value is 300. This parameter is optional but if you specify a value for it, you must also specify a value for <code>SizeInMBs</code>, and vice versa.</p>
    pub fn set_interval_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.interval_in_seconds = input;
        self
    }
    /// <p>Buffer incoming data for the specified period of time, in seconds, before delivering it to the destination. The default value is 300. This parameter is optional but if you specify a value for it, you must also specify a value for <code>SizeInMBs</code>, and vice versa.</p>
    pub fn get_interval_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.interval_in_seconds
    }
    /// Consumes the builder and constructs a [`BufferingHints`](crate::types::BufferingHints).
    pub fn build(self) -> crate::types::BufferingHints {
        crate::types::BufferingHints {
            size_in_mbs: self.size_in_mbs,
            interval_in_seconds: self.interval_in_seconds,
        }
    }
}