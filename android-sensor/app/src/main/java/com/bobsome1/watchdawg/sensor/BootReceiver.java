package com.bobsome1.watchdawg.sensor;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Restores only a schedule that the device owner explicitly enabled. */
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction())) {
            try {
                CollectionScheduler.restoreIfEnabled(context.getApplicationContext());
            } catch (RuntimeException ignored) {
                // The user can retry from the visible app; avoid boot-loop logging.
            }
        }
    }
}
