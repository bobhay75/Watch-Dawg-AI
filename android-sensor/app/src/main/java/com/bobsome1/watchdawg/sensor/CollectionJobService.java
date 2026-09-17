package com.bobsome1.watchdawg.sensor;

import android.app.job.JobParameters;
import android.app.job.JobService;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class CollectionJobService extends JobService {
    private final Object runLock = new Object();
    private final JobRunGate runGate = new JobRunGate();
    private ActiveRun activeRun;

    @Override
    public boolean onStartJob(JobParameters parameters) {
        final ActiveRun run;
        synchronized (runLock) {
            // JobScheduler does not normally overlap one JobInfo, but refusing an
            // unexpected second callback is safer than losing ownership of the first.
            if (activeRun != null) {
                return false;
            }
            run = new ActiveRun(
                    runGate.open(),
                    parameters,
                    Executors.newSingleThreadExecutor());
            activeRun = run;
            try {
                // Publish the Future while holding the ownership lock. A stop callback
                // can therefore never observe this run before its cancellable task.
                run.pending = run.executor.submit(() -> {
                    try {
                        SignedSnapshotStore.collectAndSave(getApplicationContext());
                    } catch (Exception ignored) {
                        // A later job retries. No sensitive device data or credentials
                        // are logged.
                    } finally {
                        finishIfActive(run);
                    }
                });
            } catch (RuntimeException submissionFailure) {
                runGate.stop(run.token);
                activeRun = null;
                run.executor.shutdownNow();
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters parameters) {
        ActiveRun stopped;
        synchronized (runLock) {
            stopped = activeRun;
            // JobParameters delivered to onStopJob is only guaranteed to describe
            // the same job; Binder need not preserve Java object identity.
            if (stopped == null
                    || stopped.parameters.getJobId() != parameters.getJobId()) {
                return false;
            }
            if (!runGate.stop(stopped.token)) {
                return false;
            }
            activeRun = null;
        }
        stopped.cancel();
        return true;
    }

    @Override
    public void onDestroy() {
        ActiveRun stopped;
        synchronized (runLock) {
            stopped = activeRun;
            if (stopped != null && runGate.stop(stopped.token)) {
                activeRun = null;
            } else {
                stopped = null;
            }
        }
        if (stopped != null) {
            stopped.cancel();
        }
        super.onDestroy();
    }

    private void finishIfActive(ActiveRun run) {
        try {
            synchronized (runLock) {
                if (activeRun != run || !runGate.complete(run.token)) {
                    return;
                }
                activeRun = null;
                // Keep completion ordered with the stop gate. If onStopJob won the
                // lock, completion is suppressed; if this won, the framework sees
                // jobFinished before any later stale stop callback can acquire it.
                jobFinished(run.parameters, false);
            }
        } finally {
            run.executor.shutdown();
        }
    }

    private static final class ActiveRun {
        private final long token;
        private final JobParameters parameters;
        private final ExecutorService executor;
        private volatile Future<?> pending;

        private ActiveRun(
                long token,
                JobParameters parameters,
                ExecutorService executor) {
            this.token = token;
            this.parameters = parameters;
            this.executor = executor;
        }

        private void cancel() {
            Future<?> task = pending;
            if (task != null) {
                task.cancel(true);
            }
            executor.shutdownNow();
        }
    }
}
