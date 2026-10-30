package com.sentinelstream.audit.adapter.s3;

import com.sentinelstream.audit.application.LockedObjectStore;
import com.sentinelstream.shared.config.SentinelProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketAlreadyOwnedByYouException;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.ObjectLockMode;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;

/**
 * S3-compatible store (versitygw in the demo). The bucket is created with object lock enabled and
 * every object is written with a COMPLIANCE retention date and If-None-Match, so neither this service
 * nor anyone holding its credentials can overwrite or delete a sealed batch before it expires.
 */
public class S3LockedObjectStore implements LockedObjectStore {

    private static final Logger log = LoggerFactory.getLogger(S3LockedObjectStore.class);

    private final S3Client s3;
    private final String bucket;
    private volatile boolean bucketReady;

    public S3LockedObjectStore(SentinelProperties.Audit cfg) {
        this.bucket = cfg.bucket();
        this.s3 = S3Client.builder()
                .endpointOverride(URI.create(cfg.s3Endpoint()))
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(cfg.s3AccessKey(), cfg.s3SecretKey())))
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .httpClient(UrlConnectionHttpClient.create())
                .build();
    }

    private void ensureBucket() {
        if (bucketReady) {
            return;
        }
        try {
            s3.headBucket(b -> b.bucket(bucket));
        } catch (NoSuchBucketException e) {
            try {
                s3.createBucket(b -> b.bucket(bucket).objectLockEnabledForBucket(true));
                log.info("created audit bucket {} with object lock", bucket);
            } catch (BucketAlreadyOwnedByYouException ignored) {
                // another instance won the race
            }
        } catch (S3Exception e) {
            if (e.statusCode() != 404) {
                throw e;
            }
            s3.createBucket(b -> b.bucket(bucket).objectLockEnabledForBucket(true));
        }
        bucketReady = true;
    }

    @Override
    public void putLocked(String key, byte[] body, Instant retainUntil) {
        ensureBucket();
        s3.putObject(b -> b.bucket(bucket).key(key).contentType("text/tab-separated-values")
                        .objectLockMode(ObjectLockMode.COMPLIANCE).objectLockRetainUntilDate(retainUntil).ifNoneMatch("*"),
                RequestBody.fromBytes(body));
    }

    @Override
    public byte[] get(String key) {
        ensureBucket();
        return s3.getObjectAsBytes(b -> b.bucket(bucket).key(key)).asByteArray();
    }

    @Override
    public Optional<Retention> retention(String key) {
        try {
            var r = s3.getObjectRetention(b -> b.bucket(bucket).key(key)).retention();
            return r == null ? Optional.empty() : Optional.of(new Retention(r.modeAsString(), r.retainUntilDate()));
        } catch (S3Exception e) {
            return Optional.empty();
        }
    }
}
