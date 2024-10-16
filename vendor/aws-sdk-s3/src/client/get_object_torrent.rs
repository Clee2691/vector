// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetObjectTorrent`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`bucket(impl Into<String>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::bucket) / [`set_bucket(Option<String>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::set_bucket):<br>required: **true**<br><p>The name of the bucket containing the object for which to get the torrent files.</p><br>
    ///   - [`key(impl Into<String>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::key) / [`set_key(Option<String>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::set_key):<br>required: **true**<br><p>The object key for which to get the information.</p><br>
    ///   - [`request_payer(RequestPayer)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::request_payer) / [`set_request_payer(Option<RequestPayer>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::set_request_payer):<br>required: **false**<br><p>Confirms that the requester knows that they will be charged for the request. Bucket owners need not specify this parameter in their requests. If either the source or destination S3 bucket has Requester Pays enabled, the requester will pay for corresponding charges to copy the object. For information about downloading objects from Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html">Downloading Objects in Requester Pays Buckets</a> in the <i>Amazon S3 User Guide</i>.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note><br>
    ///   - [`expected_bucket_owner(impl Into<String>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::expected_bucket_owner) / [`set_expected_bucket_owner(Option<String>)`](crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::set_expected_bucket_owner):<br>required: **false**<br><p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><br>
    /// - On success, responds with [`GetObjectTorrentOutput`](crate::operation::get_object_torrent::GetObjectTorrentOutput) with field(s):
    ///   - [`body(ByteStream)`](crate::operation::get_object_torrent::GetObjectTorrentOutput::body): <p>A Bencoded dictionary as defined by the BitTorrent specification</p>
    ///   - [`request_charged(Option<RequestCharged>)`](crate::operation::get_object_torrent::GetObjectTorrentOutput::request_charged): <p>If present, indicates that the requester was successfully charged for the request.</p> <note>   <p>This functionality is not supported for directory buckets.</p>  </note>
    /// - On failure, responds with [`SdkError<GetObjectTorrentError>`](crate::operation::get_object_torrent::GetObjectTorrentError)
    pub fn get_object_torrent(&self) -> crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder {
        crate::operation::get_object_torrent::builders::GetObjectTorrentFluentBuilder::new(self.handle.clone())
    }
}