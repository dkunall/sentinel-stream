package com.sentinelstream.detection.domain.engine;

/** LOW-confidence signals are kept as alerts but never open an incident on their own. */
public enum Confidence {
    LOW, HIGH
}
