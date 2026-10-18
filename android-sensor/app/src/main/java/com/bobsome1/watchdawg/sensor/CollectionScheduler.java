package com.bobsome1.watchdawg.sensor;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;

/** Opt-in periodic collection. The job appends to the bounded outbox and never uploads. */
public final class CollectionScheduler {
    private static final int JOB_ID = 0x57444731;
    private static final String PREFERENCES = "watchdawg_schedule";
    private static final String ENABLED = "enabled";
    private static final long INTERVAL_MILLIS = 15L * 60L * 1000L;
    private static final PeriodicCollectionGate PUBLICATION_GATE =
            new PeriodicCollectionGate();

    private CollectionScheduler() {}

    public static void enable(Context context) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (scheduler == null) {
            throw new IllegalStateException("Android JobScheduler is unavailable");
        }
        JobInfo job = new JobInfo.Builder(
                JOB_ID,
                new ComponentName(context, CollectionJobService.class))
                .setPeriodic(INTERVAL_MILLIS)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_NONE)
                .build();
        if (scheduler.schedule(job) != JobScheduler.RESULT_SUCCESS) {
            throw new IllegalStateException("Android rejected the periodic collection job");
        }
        if (!context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit().putBoolean(ENABLED, true).commit()) {
            // SharedPreferences can update its in-process map even when the durable write fails.
            // Keep a stale callback from treating that failed opt-in as authorization.
            PUBLICATION_GATE.revoke();
            scheduler.cancel(JOB_ID);
            throw new IllegalStateException("Could not persist periodic collection preference");
        }
        PUBLICATION_GATE.grant();
    }

    public static void disable(Context context) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        // Revoke first. A worker that is still collecting may finish that non-durable work, but
        // cannot enqueue or checkpoint after this gate has been crossed. If publication already
        // owns the gate, revocation linearizes immediately after that publication completes.
        PUBLICATION_GATE.revoke();
        boolean persisted = false;
        try {
            persisted = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                    .edit().putBoolean(ENABLED, false).commit();
        } finally {
            if (scheduler != null) {
                scheduler.cancel(JOB_ID);
            }
        }
        if (!persisted) {
            throw new IllegalStateException("Could not persist periodic collection preference");
        }
    }

    public static boolean isEnabled(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .getBoolean(ENABLED, false);
    }

    public static void restoreIfEnabled(Context context) {
        if (isEnabled(context)) {
            enable(context);
        }
    }

    static PeriodicCollectionGate.Permit beginPeriodicRun(Context context) {
        return PUBLICATION_GATE.open(isEnabled(context));
    }

    static boolean publishIfStillEnabled(
            PeriodicCollectionGate.Permit permit,
            DurableThenCheckpoint.CheckedAction publication) throws Exception {
        return PUBLICATION_GATE.publish(permit, publication);
    }

    static void cancelPeriodicRun(PeriodicCollectionGate.Permit permit) {
        PUBLICATION_GATE.cancel(permit);
    }
}
