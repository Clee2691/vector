// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`CreateSession`](crate::operation::create_session::builders::CreateSessionFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`session_mode(SessionMode)`](crate::operation::create_session::builders::CreateSessionFluentBuilder::session_mode) / [`set_session_mode(Option<SessionMode>)`](crate::operation::create_session::builders::CreateSessionFluentBuilder::set_session_mode):<br>required: **false**<br><p>Specifies the mode of the session that will be created, either <code>ReadWrite</code> or <code>ReadOnly</code>. By default, a <code>ReadWrite</code> session is created. A <code>ReadWrite</code> session is capable of executing all the Zonal endpoint APIs on a directory bucket. A <code>ReadOnly</code> session is constrained to execute the following Zonal endpoint APIs: <code>GetObject</code>, <code>HeadObject</code>, <code>ListObjectsV2</code>, <code>GetObjectAttributes</code>, <code>ListParts</code>, and <code>ListMultipartUploads</code>.</p><br>
    ///   - [`bucket(impl Into<String>)`](crate::operation::create_session::builders::CreateSessionFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::create_session::builders::CreateSessionFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket that you create a session for.</p><br>
    /// - On success, responds with [`CreateSessionOutput`](crate::operation::create_session::CreateSessionOutput) with field(s):
    ///   - [`credentials(Option<SessionCredentials>)`](crate::operation::create_session::CreateSessionOutput::credentials): <p>The established temporary security credentials for the created session..</p>
    /// - On failure, responds with [`SdkError<CreateSessionError>`](crate::operation::create_session::CreateSessionError)
    pub fn create_session(&self) -> crate::operation::create_session::builders::CreateSessionFluentBuilder {
        crate::operation::create_session::builders::CreateSessionFluentBuilder::new(self.handle.clone())
    }
}