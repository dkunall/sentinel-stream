package com.sentinelstream.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.support.Api;
import com.sentinelstream.support.Containers;
import com.sentinelstream.support.ItBase;
import com.sentinelstream.support.Race;
import com.sentinelstream.support.TestJwt;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditIT extends ItBase {

    @Autowired
    AuditRecorder recorder;
    @Autowired
    JdbcTemplate jdbc;

    /** Each test gets its own tenant, so its audit chain starts at genesis and nothing else writes to it. */
    record Tenant(String id, Api admin) {
    }

    Tenant tenant() {
        String t = unique("aud");
        return new Tenant(t, Api.at(port).as(TestJwt.admin("admin@" + t)));
    }

    void record(String tenant, int n) {
        for (int i = 0; i < n; i++) {
            recorder.record(tenant, "tester", "test.action", "target-" + i, Map.of("i", i));
        }
    }

    @Test
    void concurrentSealsPutEveryEntryInExactlyOneBatchAndTheChainVerifies() {
        Tenant t = tenant();
        record(t.id(), 30);

        List<JsonNode> sealed = Race.run(4, i -> t.admin().post("/v1/audit/batches:seal", null).expect(200).body());
        int entries = sealed.stream().flatMap(b -> StreamSupport.stream(b.spliterator(), false)).mapToInt(b -> b.path("entries").asInt()).sum();
        assertThat(entries).isEqualTo(30);
        assertThat(jdbc.queryForObject("select count(*) from audit_log where tenant_id = ? and batch_id is null", Integer.class, t.id()))
                .isZero();

        record(t.id(), 5);
        t.admin().post("/v1/audit/batches:seal", null).expect(200);
        JsonNode batches = t.admin().get("/v1/audit/batches").expect(200).body();
        assertThat(batches).hasSize(2);
        for (JsonNode b : batches) {
            JsonNode v = t.admin().get("/v1/audit/batches/" + b.path("id").asText() + "/verify").expect(200).body();
            assertThat(v.path("valid").asBoolean()).as(v.toString()).isTrue();
            assertThat(v.path("objectLockMode").asText()).isEqualTo("COMPLIANCE");
        }
        assertThat(t.admin().get("/v1/audit/public-key").status()).isEqualTo(200);
    }

    @Test
    void editingADatabaseRowOrTheStoredObjectIsDetectedAndTheLockedVersionCannotBeDeleted() {
        Tenant t = tenant();
        record(t.id(), 4);
        JsonNode batch = t.admin().post("/v1/audit/batches:seal", null).expect(200).body().get(0);
        String id = batch.path("id").asText();
        long seq = batch.path("fromSeq").asLong();

        jdbc.update("update audit_log set actor = 'someone-else' where seq = ?", seq);
        JsonNode v = t.admin().get("/v1/audit/batches/" + id + "/verify").expect(200).body();
        assertThat(v.path("valid").asBoolean()).isFalse();
        assertThat(v.path("modifiedSeqs").get(0).asLong()).isEqualTo(seq);
        jdbc.update("update audit_log set actor = 'tester' where seq = ?", seq);
        assertThat(t.admin().get("/v1/audit/batches/" + id + "/verify").expect(200).body().path("valid").asBoolean()).isTrue();

        try (S3Client s3 = s3()) {
            String key = batch.path("objectKey").asText();
            var versions = s3.listObjectVersions(b -> b.bucket("audit-it").prefix(key)).versions();
            assertThat(versions).hasSize(1);
            String locked = versions.getFirst().versionId();
            assertThatThrownBy(() -> s3.deleteObject(b -> b.bucket("audit-it").key(key).versionId(locked)))
                    .isInstanceOf(S3Exception.class);

            s3.putObject(b -> b.bucket("audit-it").key(key), RequestBody.fromString("# forged\n"));
            JsonNode afterForge = t.admin().get("/v1/audit/batches/" + id + "/verify").expect(200).body();
            assertThat(afterForge.path("valid").asBoolean()).isFalse();
            assertThat(afterForge.path("objectDigestOk").asBoolean()).isFalse();
            assertThat(s3.listObjectVersions(b -> b.bucket("audit-it").prefix(key)).versions().stream()
                    .map(x -> x.versionId())).contains(locked);
        }
    }

    @Test
    void auditIsAdminOnlyAndTenantScoped() {
        Tenant t = tenant();
        record(t.id(), 1);
        String id = t.admin().post("/v1/audit/batches:seal", null).expect(200).body().get(0).path("id").asText();
        acmeAdmin.get("/v1/audit/batches/" + id + "/verify").expect(404);
        Api.at(port).as(TestJwt.analyst("analyst@" + t.id())).get("/v1/audit/batches").expect(403);
    }

    static S3Client s3() {
        return S3Client.builder().endpointOverride(URI.create(Containers.s3Endpoint())).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(Containers.S3_ACCESS, Containers.S3_SECRET)))
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .httpClient(UrlConnectionHttpClient.create()).build();
    }
}
