package com.sentinelstream.detection.domain.engine;

/** Online mean and variance (Welford). Public fields so the state store can serialize it as-is. */
public final class Welford {
    public long n;
    public double mean;
    public double m2;

    public void add(double x) {
        n++;
        double d = x - mean;
        mean += d / n;
        m2 += d * (x - mean);
    }

    /** Sample variance; 0 until there are two observations. */
    public double variance() {
        return n < 2 ? 0 : m2 / (n - 1);
    }

    public double stddev() {
        return Math.sqrt(variance());
    }
}
