package com.sentinelstream.response.adapter.redis;

import com.sentinelstream.response.application.SignalSeen;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/** Best effort: if Redis is down, every signal simply goes to the database check. */
@Component
class RedisSignalSeen implements SignalSeen {

    private static final Logger log = LoggerFactory.getLogger(RedisSignalSeen.class);
    private static final Duration TTL = Duration.ofHours(1);

    private final StringRedisTemplate redis;

    RedisSignalSeen(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public boolean seen(String signalId) {
        try {
            return Boolean.TRUE.equals(redis.hasKey("signal:" + signalId));
        } catch (RuntimeException e) {
            log.debug("redis unavailable for signal dedup: {}", e.toString());
            return false;
        }
    }

    @Override
    public void remember(String signalId) {
        try {
            redis.opsForValue().set("signal:" + signalId, "1", TTL);
        } catch (RuntimeException e) {
            log.debug("redis unavailable for signal dedup: {}", e.toString());
        }
    }
}
