package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

public final class PhoneGuardDecisionTest {
    @Test
    public void unexpectedContainsOnlyPackagesOutsideApprovedBaseline() {
        Set<String> result = PhoneGuardDecision.unexpected(
                new HashSet<>(Arrays.asList("approved.one", "approved.two")),
                new HashSet<>(Arrays.asList("approved.one", "new.game", "new.tool")));

        assertEquals(
                new HashSet<>(Arrays.asList("new.game", "new.tool")),
                result);
    }

    @Test
    public void pendingAlertsSkipsAlreadyAlertedAndRespectsLimit() {
        Set<String> result = PhoneGuardDecision.pendingAlerts(
                new HashSet<>(Arrays.asList("app.a", "app.b", "app.c")),
                new HashSet<>(Arrays.asList("app.a")),
                1);

        assertEquals(new HashSet<>(Arrays.asList("app.b")), result);
    }
}
