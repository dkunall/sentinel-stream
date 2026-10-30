package com.sentinelstream.ingest.adapter.redis;

import com.sentinelstream.ingest.application.IngestDedup;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/** SET NX with a TTL: one round trip, atomic across app instances. */
@Component
class RedisIngestDedup implements IngestDedup {

    private final StringRedisTemplate redis;

    RedisIngestDedup(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public boolean claim(String tenant, String eventId, Duration ttl) {
        return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key(tenant, eventId), "1", ttl));
    }

    @Override
    public void release(String tenant, String eventId) {
        redis.delete(key(tenant, eventId));
    }

    private static String key(String tenant, String id) {
        return "ingest:" + tenant + ":" + id;
    }
}
