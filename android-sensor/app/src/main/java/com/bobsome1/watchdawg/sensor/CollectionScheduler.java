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
            scheduler.cancel(JOB_ID);
            throw new IllegalStateException("Could not persist periodic collection preference");
        }
    }

    public static void disable(Context context) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (scheduler != null) {
            scheduler.cancel(JOB_ID);
        }
        if (!context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit().putBoolean(ENABLED, false).commit()) {
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
}
