# radosgw-admin-client

Manage the users and buckets of a
[Ceph Object Gateway](https://docs.ceph.com/en/latest/radosgw/)
instance via its
[Admin Operations API](https://docs.ceph.com/en/latest/radosgw/adminops/)


## Installation

Install this Python package directly from GitHub:

    python3 -m pip install git+https://github.com/HTPhenotyping/radosgw_admin_client.git@{tag}


## Configuration

The object gateway instance and the user with which to manage it are defined
via environment variables:

    export RADOSGW_HOST=s3.example.com
    export RADOSGW_ACCESS_KEY=...
    export RADOSGW_SECRET_KEY=...

The access and secret keys must be for a user with the following capabilities:

- `buckets=*`
- `metadata=read`
- `usage=read`
- `users=*`
- `zone=read`

Do **not** use this user for any other purpose.


## Usage

    radosgw-admin-client {subcommand} ...

Use `--help` to list required arguments and options.

Subcommands fall into several broad categories:

- Users: `get-users`, `create-user`, `delete-user`, `get-quota`, `set-quota`
- Buckets: `get-buckets`, `get-bucket`, `create-bucket`
- Policies: `get-policy`, `allow-read`, `allow-public-read`, `allow-write`, `make-private`

Quotas are managed here only on a per-user basis, and policies always apply
to all objects in a bucket.
