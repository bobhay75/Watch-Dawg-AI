package com.bobsome1.watchdawg.sensor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

public final class SingleRequestTest {
    @Test public void repeatedRequestCancelsOldListenerAndTimeoutBeforeReplacing() {
        SingleRequest<Object> requests = new SingleRequest<>();
        Object first = new Object();
        Object second = new Object();
        List<String> cleanup = new ArrayList<>();
        requests.replace(first, () -> {
            assertFalse(requests.isCurrent(first));
            cleanup.add("listener");
            cleanup.add("timeout");
        });
        requests.replace(second, () -> {});
        assertEquals(Arrays.asList("listener", "timeout"), cleanup);
        assertFalse(requests.isCurrent(first));
        assertTrue(requests.isCurrent(second));
    }

    @Test public void destroyCleanupIsIdempotentAndRejectsStaleCallbacks() {
        SingleRequest<Object> requests = new SingleRequest<>();
        Object listener = new Object();
        List<String> cleanup = new ArrayList<>();
        requests.replace(listener, () -> cleanup.add("cancelled"));
        requests.clear();
        requests.clear();
        assertFalse(requests.isCurrent(listener));
        assertEquals(Arrays.asList("cancelled"), cleanup);
    }

    @Test public void revokedPermissionCannotLeaveRequestCurrentAfterCleanupThrows() {
        SingleRequest<Object> requests = new SingleRequest<>();
        Object listener = new Object();
        requests.replace(listener, () -> { throw new SecurityException("revoked"); });
        assertThrows(SecurityException.class, requests::clear);
        assertFalse(requests.isCurrent(listener));
        requests.clear();
    }
}
