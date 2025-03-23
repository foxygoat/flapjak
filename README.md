# flapjak

Featherweight LDAP server configured with jsonnet and Kubernetes.

I need a little LDAP server. I don't have many records to serve, but some record
types I want to serve are `automountMap` and `automount`. None of the little
LDAP servers I can find serve these records. So I run OpenLDAP in order to serve
these. It is big and complicated and annoying to restore from backup for my
situation.

So, using [gldap], it seems I should be able to serve any sort of record I want.
I would not want to deploy a large-scale LDAP server with this repo, but it's
not for that.

The "jsonnet" bit is because I add a sprinkling of jsonnet anywhere it makes
sense. All the records I configure will be configured via jsonnet. As there is a
bunch of repeated values in attributes across the records, jsonnet works well to
eliminate that duplication.

I would also like to be able to deploy applications on Kubernetes that need
their own UID/GID for NFS storage. I want to deploy these IDs along with the
applications, so flapjak can also be configured with CRDs.

jsonnet can be consider static config to this application. One day, it may use a
DB to store record and allow them to be updated. Today is not that day. Today
the records will all be specified in jsonnet configs or Kubernetes CRDs.

[gldap]: https://github.com/jimlambrt/gldap
