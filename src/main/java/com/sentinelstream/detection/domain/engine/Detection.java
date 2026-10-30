package com.sentinelstream.detection.domain.engine;

import java.util.List;

/** What a detector found; the engine turns it into a {@link Signal}. */
public record Detection(List<String> eventIds, Confidence confidence, String summary) {
}
