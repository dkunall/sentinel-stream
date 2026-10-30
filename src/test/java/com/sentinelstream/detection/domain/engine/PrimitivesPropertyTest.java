package com.sentinelstream.detection.domain.engine;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.data.Offset.offset;

class PrimitivesPropertyTest {

    @Provide
    Arbitrary<String> small() {
        return Arbitraries.strings().withChars("abc").ofMinLength(1).ofMaxLength(4);
    }

    @Provide
    Arbitrary<String> text() {
        return Arbitraries.strings().withChars("abcABx").ofMaxLength(60);
    }

    @Property(tries = 500)
    void ahoCorasickFindsExactlyThePatternsThatOccur(@ForAll @Size(max = 8) List<@net.jqwik.api.From("small") String> patterns,
                                                     @ForAll("text") String text) {
        var ac = new AhoCorasick(patterns);
        Set<String> expected = new HashSet<>();
        for (String p : patterns) {
            if (text.toLowerCase().contains(p)) {
                expected.add(p);
            }
        }
        assertThat(new HashSet<>(ac.findAll(text))).isEqualTo(expected);
        assertThat(ac.firstMatch(text).isPresent()).isEqualTo(!expected.isEmpty());
    }

    @Property(tries = 300)
    void welfordMatchesTheTwoPassFormula(@ForAll @Size(min = 2, max = 200) List<@net.jqwik.api.constraints.DoubleRange(min = -1e3, max = 1e3) Double> xs) {
        var w = new Welford();
        xs.forEach(w::add);
        double mean = xs.stream().mapToDouble(Double::doubleValue).average().orElseThrow();
        double var = xs.stream().mapToDouble(x -> (x - mean) * (x - mean)).sum() / (xs.size() - 1);
        assertThat(w.mean).isCloseTo(mean, offset(1e-6));
        assertThat(w.variance()).isCloseTo(var, offset(1e-6 * Math.max(1, var)));
    }

    @Test
    void haversineKnownDistances() {
        // Bengaluru to Frankfurt, synthetic coordinates from the bundled table
        assertThat(Haversine.km(12.97, 77.59, 50.11, 8.68)).isBetween(7_300.0, 7_500.0);
        assertThat(Haversine.km(10, 10, 10, 10)).isZero();
        assertThat(Haversine.km(0, 0, 0, 180)).isCloseTo(Math.PI * 6371.0088, offset(1.0));
    }
}
