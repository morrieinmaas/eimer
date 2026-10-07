# Engine support for bucket features

The migration carry-over table in `internal/audit/migration.go` was verified against each
engine's own documentation and repository on 2026-10-07. Levels: `native` means the S3 API
works as specified, `partial` means limits or a non-S3 mechanism, `none` means not implemented.
Corrections welcome as a pull request that cites a source.

| feature | RustFS 1.0 | Garage | SeaweedFS | Ceph RGW |
|---|---|---|---|---|
| versioning | native [1][2] | none [3] | native [4][5], no MFA delete | native [6] |
| object lock | native [1][2] | none [3] | native [7], set at bucket creation, max 100 years | native [8][9] |
| bucket policy | native [10] | none [3], per-key grants instead | native [11], 2012-10-17 JSON | native [6] |
| ACL grants | partial [2][12]: canned headers accepted, XML grants rejected, not enforced | none [3] | partial [13][4]: canned ACLs map to file modes, grant persistence in flight [14] | native [6] |
| lifecycle | native [2][15]: transitions need an admin-registered tier | partial [3]: expiration and abort multipart only | partial [16]: no transition rules | native [6][17] |
| replication | native [18]: target registered via admin API, both buckets versioned | none [3]: cluster-internal replication factor only | partial [4][19]: filer.sync, not the S3 API | partial [6][20]: only across multisite zones |
| event notifications | native [21]: QueueConfiguration only | none [3] | partial [4][22]: filer-wide notification.toml | native [6][23]: TopicConfiguration via SNS |
| default encryption | native [24][25]: needs a KMS backend [26] | none [3]: encrypt the partition or client side | native [27][4]: needs KEK or KMS provider | native [28]: SSE-S3 needs Vault |
| bucket tags | native [2] | none [3] | native [4] | native [6] |
| CORS | native [2][29] | native [3] | native [4] | native [30] |
| access logging | partial [2][31]: handlers store config, delivery listed as planned | none [3] | none [4] | native [32][6] |

Sources

1. https://github.com/rustfs/rustfs
2. https://docs.rustfs.com/en/reference/s3-compatibility
3. https://garagehq.deuxfleurs.fr/documentation/reference-manual/s3-compatibility/
4. https://github.com/seaweedfs/seaweedfs/wiki/Amazon-S3-API
5. https://github.com/seaweedfs/seaweedfs/wiki/S3-Object-Versioning
6. https://docs.ceph.com/en/latest/radosgw/s3/
7. https://github.com/seaweedfs/seaweedfs/wiki/S3-Object-Lock-and-Retention
8. https://docs.ceph.com/en/latest/radosgw/s3/bucketops/
9. https://docs.ceph.com/en/latest/radosgw/s3/objectops/
10. https://docs.rustfs.com/en/administration/data/bucket/policy
11. https://github.com/seaweedfs/seaweedfs/wiki/S3-Bucket-Policies
12. https://github.com/rustfs/rustfs/blob/main/rustfs/src/storage/ecfs.rs
13. https://github.com/seaweedfs/seaweedfs/wiki/S3-Configuration
14. https://github.com/seaweedfs/seaweedfs/pull/11588
15. https://github.com/rustfs/rustfs/blob/main/crates/ecstore/src/services/tier/tier.rs
16. https://github.com/seaweedfs/seaweedfs/wiki/S3-Lifecycle
17. https://docs.ceph.com/en/latest/radosgw/placement/
18. https://docs.rustfs.com/en/administration/data/bucket/replication
19. https://github.com/seaweedfs/seaweedfs/wiki/Filer-Active-Active-cross-cluster-continuous-synchronization
20. https://docs.ceph.com/en/latest/radosgw/multisite-sync-policy/
21. https://docs.rustfs.com/en/operations/event-notifications
22. https://github.com/seaweedfs/seaweedfs/wiki/Async-Replication-to-Cloud
23. https://docs.ceph.com/en/latest/radosgw/s3-notification-compatibility/
24. https://docs.rustfs.com/en/security-compliance/encryption
25. https://github.com/rustfs/rustfs/blob/main/crates/e2e_test/src/kms/bucket_default_encryption_test.rs
26. https://github.com/rustfs/rustfs/issues/1278
27. https://github.com/seaweedfs/seaweedfs/wiki/Server-Side-Encryption
28. https://docs.ceph.com/en/latest/radosgw/encryption/
29. https://docs.rustfs.com/en/administration/cors
30. https://docs.ceph.com/en/latest/radosgw/config-ref/
31. https://github.com/rustfs/rustfs/blob/main/docs/architecture/s3-compatibility-matrix.md
32. https://docs.ceph.com/en/latest/radosgw/bucket_logging/
