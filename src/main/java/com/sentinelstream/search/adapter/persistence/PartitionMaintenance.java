package com.sentinelstream.search.adapter.persistence;

import com.sentinelstream.shared.config.SentinelProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.regex.Pattern;

/**
 * One partition per UTC day. Partitions exist from {@code retention} days back to two days ahead, so
 * any event the normalizer accepts (at most 30 days old, 5 minutes ahead) has a home; there is no
 * default partition, so a gap shows up as an insert error instead of silently piling rows in one table.
 * Retention is a {@code DROP TABLE} of whole days, not a slow {@code DELETE}.
 */
@Component
public class PartitionMaintenance implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(PartitionMaintenance.class);
    private static final DateTimeFormatter NAME = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final Pattern PARTITION = Pattern.compile("event_p(\\d{8})");
    private static final long LOCK_KEY = 0x5e47_0001L;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final int retentionDays;

    PartitionMaintenance(JdbcTemplate jdbc, TransactionTemplate tx, Clock clock, SentinelProperties props) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.clock = clock;
        this.retentionDays = props.events().retentionDays();
    }

    @Override
    public void afterPropertiesSet() {
        maintain();
    }

    @Scheduled(cron = "0 5 * * * *")
    public void maintain() {
        tx.executeWithoutResult(s -> {
            jdbc.queryForObject("select pg_advisory_xact_lock(?)", Object.class, LOCK_KEY);
            LocalDate today = LocalDate.now(clock.withZone(ZoneOffset.UTC));
            int created = 0;
            for (LocalDate d = today.minusDays(retentionDays + 1L); !d.isAfter(today.plusDays(2)); d = d.plusDays(1)) {
                created += ensure(d);
            }
            int dropped = 0;
            LocalDate oldest = today.minusDays(retentionDays + 1L);
            for (String name : partitions()) {
                var m = PARTITION.matcher(name);
                if (m.matches() && LocalDate.parse(m.group(1), NAME).isBefore(oldest)) {
                    jdbc.execute("drop table " + name);
                    dropped++;
                }
            }
            if (created + dropped > 0) {
                log.info("event partitions: {} created, {} dropped", created, dropped);
            }
        });
    }

    private int ensure(LocalDate day) {
        String name = "event_p" + NAME.format(day);
        Boolean exists = jdbc.queryForObject("select to_regclass(?) is not null", Boolean.class, name);
        if (Boolean.TRUE.equals(exists)) {
            return 0;
        }
        jdbc.execute("create table " + name + " partition of event for values from ('" + day + " 00:00:00+00') to ('"
                + day.plusDays(1) + " 00:00:00+00')");
        return 1;
    }

    List<String> partitions() {
        return jdbc.queryForList("""
                select c.relname from pg_inherits i join pg_class c on c.oid = i.inhrelid
                where i.inhparent = 'event'::regclass order by c.relname
                """, String.class);
    }
}
