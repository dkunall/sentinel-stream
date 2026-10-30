package com.sentinelstream.ingest.adapter.syslog;

import com.sentinelstream.ingest.application.IngestService;
import com.sentinelstream.shared.config.SentinelProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

/**
 * Syslog over TCP with newline framing (RFC 6587 non-transparent framing; octet counting is not
 * supported). All lines are attributed to one configured tenant: plain syslog carries no
 * authentication, so this listener should only ever be bound to a trusted interface.
 */
@Component
class SyslogServer implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(SyslogServer.class);
    static final int MAX_LINE = 8192;
    private static final int MAX_CONNECTIONS = 64;
    private static final int IDLE_TIMEOUT_MS = 300_000;

    private final IngestService ingest;
    private final SentinelProperties.Syslog config;
    private final Semaphore connections = new Semaphore(MAX_CONNECTIONS);
    private final Set<Socket> open = ConcurrentHashMap.newKeySet();
    private final Counter lines;
    private final Counter dropped;
    private volatile ServerSocket server;

    SyslogServer(IngestService ingest, SentinelProperties props, MeterRegistry meters) {
        this.ingest = ingest;
        this.config = props.syslog();
        this.lines = meters.counter("sentinel.syslog.lines", "result", "queued");
        this.dropped = meters.counter("sentinel.syslog.lines", "result", "dropped");
    }

    @Override
    public void start() {
        if (!config.enabled()) {
            return;
        }
        try {
            ServerSocket s = new ServerSocket();
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(InetAddress.getByName(config.bind()), config.port()));
            server = s;
        } catch (IOException e) {
            throw new IllegalStateException("cannot bind syslog listener on " + config.bind() + ":" + config.port(), e);
        }
        Thread.ofVirtual().name("syslog-accept").start(this::acceptLoop);
        log.info("Syslog TCP listener on {}:{} for tenant {}", config.bind(), port(), config.tenant());
    }

    int port() {
        return server == null ? -1 : server.getLocalPort();
    }

    private void acceptLoop() {
        while (server != null && !server.isClosed()) {
            try {
                Socket socket = server.accept();
                if (!connections.tryAcquire()) {
                    socket.close();
                    continue;
                }
                open.add(socket);
                Thread.ofVirtual().name("syslog-conn").start(() -> serve(socket));
            } catch (IOException e) {
                if (server != null && !server.isClosed()) {
                    log.warn("syslog accept failed: {}", e.toString());
                }
            }
        }
    }

    private void serve(Socket socket) {
        try (socket; InputStream in = new BufferedInputStream(socket.getInputStream())) {
            socket.setSoTimeout(IDLE_TIMEOUT_MS);
            ByteArrayOutputStream line = new ByteArrayOutputStream(512);
            boolean overlong = false;
            int b;
            while ((b = in.read()) >= 0) {
                if (b == '\n') {
                    if (!overlong && line.size() > 0) {
                        handle(line.toString(StandardCharsets.UTF_8));
                    } else if (overlong) {
                        dropped.increment();
                    }
                    line.reset();
                    overlong = false;
                } else if (!overlong) {
                    if (line.size() >= MAX_LINE) {
                        overlong = true;
                        line.reset();
                    } else {
                        line.write(b);
                    }
                }
            }
            if (!overlong && line.size() > 0) {
                handle(line.toString(StandardCharsets.UTF_8));
            }
        } catch (SocketTimeoutException e) {
            log.debug("syslog connection idle, closing");
        } catch (IOException e) {
            log.debug("syslog connection ended: {}", e.toString());
        } finally {
            open.remove(socket);
            connections.release();
        }
    }

    private void handle(String raw) {
        String text = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
        try {
            ingest.ingestSyslog(config.tenant(), text);
            lines.increment();
        } catch (RuntimeException e) {
            dropped.increment();
            log.warn("syslog line dropped: {}", e.getMessage());
        }
    }

    @Override
    public void stop() {
        ServerSocket s = server;
        server = null;
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
        for (Socket socket : open) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
    }

    @Override
    public boolean isRunning() {
        return server != null;
    }
}
