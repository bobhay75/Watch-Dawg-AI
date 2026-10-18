package com.bobsome1.watchdawg.sensor;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

/** Owner-facing notifications for apps outside the approved Phone Guard baseline. */
final class PhoneGuardNotifications {
    private static final String CHANNEL_ID = "watchdawg_phone_guard";

    private PhoneGuardNotifications() {}

    static void ensureChannel(Context context) {
        NotificationManager manager = (NotificationManager) context.getSystemService(
                Context.NOTIFICATION_SERVICE);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Watch-Dawg Phone Guard",
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Alerts when Watch-Dawg finds an app outside your approved baseline.");
        manager.createNotificationChannel(channel);
    }

    static boolean notificationsEnabled(Context context) {
        NotificationManager manager = (NotificationManager) context.getSystemService(
                Context.NOTIFICATION_SERVICE);
        if (manager == null) {
            return false;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        return manager.areNotificationsEnabled();
    }

    static boolean notifyUnexpectedApp(
            Context context,
            String label,
            String packageName,
            InstallSourceEvidence.Source source) {
        ensureChannel(context);
        if (!notificationsEnabled(context)) {
            return false;
        }
        Intent review = new Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:" + packageName));
        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                packageName.hashCode(),
                review,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        String detail = label + " was found outside your approved app baseline. Installer: "
                + source.bestInstaller() + ". Source: " + source.sourceKind
                + ". Tap to review the app in Android Settings.";
        Notification notification = new Notification.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_watch_dawg_guard)
                .setContentTitle("Watch-Dawg: unapproved app detected")
                .setContentText(detail)
                .setStyle(new Notification.BigTextStyle().bigText(detail))
                .setCategory(Notification.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build();
        NotificationManager manager = (NotificationManager) context.getSystemService(
                Context.NOTIFICATION_SERVICE);
        if (manager == null) {
            return false;
        }
        manager.notify(0x57440000 ^ packageName.hashCode(), notification);
        return true;
    }
}
