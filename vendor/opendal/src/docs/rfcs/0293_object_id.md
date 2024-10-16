- Proposal Name: `object_id`
- Start Date: 2022-05-27
- RFC PR: [apache/opendal#293](https://github.com/apache/opendal/pull/293)
- Tracking Issue: [apache/opendal#294](https://github.com/apache/opendal/issues/294)

# Summary

Allow getting id from an object.

# Motivation

Allow get id from an object will make it possible to operate across different operators. Users can store objects' IDs locally and refer to them with different settings. This proposal will make tasks like backup, restore, and migration possible.

# Guide-level explanation

Users can fetch an object id via:

```rust
let o = op.object("test_object");
let id = o.id();
```

The id is unique and permanent inside the underlying storage.

For example, if we have an s3 bucket with the root `/workdir/`, the object's id `test_object` will be `/workdir/test_object`.

# Reference-level explanation

`id()` and `path()` will be added as functions of `object`:

```rust
impl Object {
    pub fn id(&self) -> String {}
    pub fn path(&self) -> String {}
}
```

- `path` is a re-export of call to `Metadata::path()`.
- `id` will be generated by Operator's root and `Metadata::path()`.

# Drawbacks

None

# Rationale and alternatives

## Why not add a new field in `Metadata`?

Adding a new field inside `Metadata` requires every service to handle the id separately. And every metadata will need to store a complete id with the operators' root.

## Why not provide a full URI like `s3://path/to/object`?

Because we can't.

A full and functional URI towards an object will need the operator's endpoint and credentials. It's better to provide the mechanism and allow users to construct them based on their own business.

# Prior art

None

# Unresolved questions

None

# Future possibilities

None