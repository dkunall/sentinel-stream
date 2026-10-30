package com.sentinelstream.pipeline.adapter.streams;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReplacementBudgetTest {

    static final long SECOND = 1_000_000_000L;

    @Test
    void aBurstOfFailuresExhaustsTheBudget() {
        var budget = new ReplacementBudget();
        for (int i = 0; i < ReplacementBudget.MAX; i++) {
            assertThat(budget.tryReplace(i * SECOND)).isTrue();
        }
        assertThat(budget.tryReplace(10 * SECOND)).isFalse();
    }

    @Test
    void failuresSpreadOutOverTimeKeepBeingReplaced() {
        var budget = new ReplacementBudget();
        for (int i = 0; i < 50; i++) {
            assertThat(budget.tryReplace(i * 20 * SECOND)).isTrue();
        }
    }
}
