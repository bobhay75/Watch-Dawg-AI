package com.bobsome1.watchdawg.sensor;

/** Maps permission and query outcomes to an evidence-coverage status. */
final class UsageSensorStatus {
    private UsageSensorStatus() {}

    static String resolve(
            boolean accessGranted, boolean queryAvailable, boolean queryComplete) {
        if (!accessGranted) {
            return "not_granted";
        }
        if (!queryAvailable) {
            return "error";
        }
        return queryComplete ? "observed" : "partial";
    }
}
