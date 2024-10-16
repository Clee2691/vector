// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the rejected events.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RejectedLogEventsInfo {
    /// <p>The log events that are too new.</p>
    pub too_new_log_event_start_index: ::std::option::Option<i32>,
    /// <p>The log events that are dated too far in the past.</p>
    pub too_old_log_event_end_index: ::std::option::Option<i32>,
    /// <p>The expired log events.</p>
    pub expired_log_event_end_index: ::std::option::Option<i32>,
}
impl RejectedLogEventsInfo {
    /// <p>The log events that are too new.</p>
    pub fn too_new_log_event_start_index(&self) -> ::std::option::Option<i32> {
        self.too_new_log_event_start_index
    }
    /// <p>The log events that are dated too far in the past.</p>
    pub fn too_old_log_event_end_index(&self) -> ::std::option::Option<i32> {
        self.too_old_log_event_end_index
    }
    /// <p>The expired log events.</p>
    pub fn expired_log_event_end_index(&self) -> ::std::option::Option<i32> {
        self.expired_log_event_end_index
    }
}
impl RejectedLogEventsInfo {
    /// Creates a new builder-style object to manufacture [`RejectedLogEventsInfo`](crate::types::RejectedLogEventsInfo).
    pub fn builder() -> crate::types::builders::RejectedLogEventsInfoBuilder {
        crate::types::builders::RejectedLogEventsInfoBuilder::default()
    }
}

/// A builder for [`RejectedLogEventsInfo`](crate::types::RejectedLogEventsInfo).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct RejectedLogEventsInfoBuilder {
    pub(crate) too_new_log_event_start_index: ::std::option::Option<i32>,
    pub(crate) too_old_log_event_end_index: ::std::option::Option<i32>,
    pub(crate) expired_log_event_end_index: ::std::option::Option<i32>,
}
impl RejectedLogEventsInfoBuilder {
    /// <p>The log events that are too new.</p>
    pub fn too_new_log_event_start_index(mut self, input: i32) -> Self {
        self.too_new_log_event_start_index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The log events that are too new.</p>
    pub fn set_too_new_log_event_start_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.too_new_log_event_start_index = input;
        self
    }
    /// <p>The log events that are too new.</p>
    pub fn get_too_new_log_event_start_index(&self) -> &::std::option::Option<i32> {
        &self.too_new_log_event_start_index
    }
    /// <p>The log events that are dated too far in the past.</p>
    pub fn too_old_log_event_end_index(mut self, input: i32) -> Self {
        self.too_old_log_event_end_index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The log events that are dated too far in the past.</p>
    pub fn set_too_old_log_event_end_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.too_old_log_event_end_index = input;
        self
    }
    /// <p>The log events that are dated too far in the past.</p>
    pub fn get_too_old_log_event_end_index(&self) -> &::std::option::Option<i32> {
        &self.too_old_log_event_end_index
    }
    /// <p>The expired log events.</p>
    pub fn expired_log_event_end_index(mut self, input: i32) -> Self {
        self.expired_log_event_end_index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The expired log events.</p>
    pub fn set_expired_log_event_end_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.expired_log_event_end_index = input;
        self
    }
    /// <p>The expired log events.</p>
    pub fn get_expired_log_event_end_index(&self) -> &::std::option::Option<i32> {
        &self.expired_log_event_end_index
    }
    /// Consumes the builder and constructs a [`RejectedLogEventsInfo`](crate::types::RejectedLogEventsInfo).
    pub fn build(self) -> crate::types::RejectedLogEventsInfo {
        crate::types::RejectedLogEventsInfo {
            too_new_log_event_start_index: self.too_new_log_event_start_index,
            too_old_log_event_end_index: self.too_old_log_event_end_index,
            expired_log_event_end_index: self.expired_log_event_end_index,
        }
    }
}