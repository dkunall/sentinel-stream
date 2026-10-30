package com.sentinelstream.ingest.adapter.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelstream.shared.config.SentinelProperties;
import com.sentinelstream.shared.web.ProblemWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Caps request bodies before Jackson buffers them. Declared lengths are checked up front; chunked
 * bodies are counted as they are read and the request fails when the cap is crossed.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class BodyLimitFilter extends OncePerRequestFilter {

    private final long max;
    private final ObjectMapper json;

    BodyLimitFilter(SentinelProperties props, ObjectMapper json) {
        this.max = props.ingest().maxBodyBytes();
        this.json = json;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (req.getContentLengthLong() > max) {
            ProblemWriter.write(res, json, HttpStatus.PAYLOAD_TOO_LARGE, "body-too-large", "request body over " + max + " bytes");
            return;
        }
        try {
            chain.doFilter(new Limited(req, max), res);
        } catch (BodyTooLarge e) {
            if (!res.isCommitted()) {
                res.reset();
                ProblemWriter.write(res, json, HttpStatus.PAYLOAD_TOO_LARGE, "body-too-large", "request body over " + max + " bytes");
            }
        }
    }

    static final class BodyTooLarge extends RuntimeException {
        BodyTooLarge() {
            super("body too large", null, false, false);
        }
    }

    private static final class Limited extends HttpServletRequestWrapper {
        private final long max;
        private ServletInputStream stream;

        Limited(HttpServletRequest req, long max) {
            super(req);
            this.max = max;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                ServletInputStream in = super.getInputStream();
                stream = new ServletInputStream() {
                    long read;

                    @Override
                    public int read() throws IOException {
                        int b = in.read();
                        if (b >= 0) {
                            count(1);
                        }
                        return b;
                    }

                    @Override
                    public int read(byte[] buf, int off, int len) throws IOException {
                        int n = in.read(buf, off, len);
                        if (n > 0) {
                            count(n);
                        }
                        return n;
                    }

                    private void count(int n) {
                        read += n;
                        if (read > max) {
                            throw new BodyTooLarge();
                        }
                    }

                    @Override
                    public boolean isFinished() {
                        return in.isFinished();
                    }

                    @Override
                    public boolean isReady() {
                        return in.isReady();
                    }

                    @Override
                    public void setReadListener(ReadListener listener) {
                        in.setReadListener(listener);
                    }
                };
            }
            return stream;
        }
    }
}
