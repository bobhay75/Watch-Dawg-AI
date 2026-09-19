package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Test;

public final class PeriodicCollectionGateTest {
    @Test
    public void revocationWhileCollectionIsInFlightRejectsPublication() throws Exception {
        PeriodicCollectionGate gate = new PeriodicCollectionGate();
        PeriodicCollectionGate.Permit permit = gate.open(true);
        AtomicBoolean published = new AtomicBoolean();

        gate.revoke();

        assertFalse(gate.publish(permit, () -> published.set(true)));
        assertFalse(published.get());
    }

    @Test
    public void reenableDoesNotRevivePermitFromPriorConsentEpoch() throws Exception {
        PeriodicCollectionGate gate = new PeriodicCollectionGate();
        PeriodicCollectionGate.Permit oldPermit = gate.open(true);

        gate.revoke();
        gate.grant();

        assertFalse(gate.publish(oldPermit, () -> {}));
        PeriodicCollectionGate.Permit newPermit = gate.open(true);
        assertNotNull(newPermit);
        assertTrue(gate.publish(newPermit, () -> {}));
    }

    @Test
    public void persistedOptOutRejectsStaleJobCallback() {
        PeriodicCollectionGate gate = new PeriodicCollectionGate();

        assertNull(gate.open(false));
    }

    @Test
    public void stoppedRunCannotPublishEvenWhenGlobalConsentRemainsEnabled() throws Exception {
        PeriodicCollectionGate gate = new PeriodicCollectionGate();
        PeriodicCollectionGate.Permit permit = gate.open(true);
        AtomicBoolean published = new AtomicBoolean();

        gate.cancel(permit);

        assertFalse(gate.publish(permit, () -> published.set(true)));
        assertFalse(published.get());
        assertNotNull(gate.open(true));
    }

    @Test
    public void failedEnableRevocationRejectsStalePersistedTrueCallback() {
        PeriodicCollectionGate gate = new PeriodicCollectionGate();
        gate.grant();

        // Models SharedPreferences updating memory before commit() reports a disk failure.
        gate.revoke();

        assertNull(gate.open(true));
    }

    @Test
    public void revocationLinearizesAfterPublicationAlreadyStarted() throws Exception {
        PeriodicCollectionGate gate = new PeriodicCollectionGate();
        PeriodicCollectionGate.Permit permit = gate.open(true);
        CountDownLatch publicationStarted = new CountDownLatch(1);
        CountDownLatch releasePublication = new CountDownLatch(1);
        CountDownLatch publicationFinished = new CountDownLatch(1);
        CountDownLatch revocationFinished = new CountDownLatch(1);

        Thread publisher = new Thread(() -> {
            try {
                gate.publish(permit, () -> {
                    publicationStarted.countDown();
                    assertTrue(releasePublication.await(5, TimeUnit.SECONDS));
                });
            } catch (Exception error) {
                throw new AssertionError(error);
            } finally {
                publicationFinished.countDown();
            }
        });
        Thread revoker = new Thread(() -> {
            gate.revoke();
            revocationFinished.countDown();
        });

        publisher.start();
        assertTrue(publicationStarted.await(5, TimeUnit.SECONDS));
        revoker.start();
        assertFalse(revocationFinished.await(100, TimeUnit.MILLISECONDS));
        releasePublication.countDown();
        assertTrue(publicationFinished.await(5, TimeUnit.SECONDS));
        assertTrue(revocationFinished.await(5, TimeUnit.SECONDS));
        publisher.join(5_000L);
        revoker.join(5_000L);
        assertFalse(publisher.isAlive());
        assertFalse(revoker.isAlive());
        assertFalse(gate.publish(permit, () -> {}));
    }
}
