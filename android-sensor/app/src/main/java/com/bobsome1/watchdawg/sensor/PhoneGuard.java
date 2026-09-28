package com.bobsome1.watchdawg.sensor;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Local owner-approved application baseline.
 *
 * Raw package names remain in app-private SharedPreferences and are never added to the
 * signed remote snapshot. Export of the latest incident is an explicit owner action.
 */
public final class PhoneGuard {
    private static final String PREFERENCES = "watchdawg_phone_guard";
    private static final String ARMED = "armed";
    private static final String APPROVED = "approved_packages";
    private static final String UNAPPROVED = "unapproved_packages";
    private static final String ALERTED = "alerted_packages";
    private static final String LAST_PACKAGE = "last_package";
    private static final String LAST_LABEL = "last_label";
    private static final String LAST_INSTALLER = "last_installer";
    private static final String LAST_INITIATOR = "last_initiator";
    private static final String LAST_ORIGINATOR = "last_originator";
    private static final String LAST_UPDATE_OWNER = "last_update_owner";
    private static final String LAST_SOURCE_KIND = "last_source_kind";
    private static final String LAST_OBSERVED_AT = "last_observed_at";
    private static final int MAX_ALERTS_PER_SCAN = 5;

    private PhoneGuard() {}

    public static int arm(Context context) {
        Set<String> installed = installedPackageNames(context.getPackageManager());
        installed.add(context.getPackageName());
        preferences(context).edit()
                .putBoolean(ARMED, true)
                .putStringSet(APPROVED, new HashSet<>(installed))
                .putStringSet(UNAPPROVED, new HashSet<>())
                .putStringSet(ALERTED, new HashSet<>())
                .remove(LAST_PACKAGE)
                .remove(LAST_LABEL)
                .remove(LAST_INSTALLER)
                .remove(LAST_INITIATOR)
                .remove(LAST_ORIGINATOR)
                .remove(LAST_UPDATE_OWNER)
                .remove(LAST_SOURCE_KIND)
                .remove(LAST_OBSERVED_AT)
                .apply();
        return installed.size();
    }

    public static void disarm(Context context) {
        preferences(context).edit()
                .putBoolean(ARMED, false)
                .putStringSet(UNAPPROVED, new HashSet<>())
                .putStringSet(ALERTED, new HashSet<>())
                .apply();
    }

    public static boolean isArmed(Context context) {
        return preferences(context).getBoolean(ARMED, false);
    }

    public static ScanResult scanAndNotify(Context context) {
        SharedPreferences state = preferences(context);
        if (!state.getBoolean(ARMED, false)) {
            return ScanResult.disarmed();
        }
        Set<String> installed = installedPackageNames(context.getPackageManager());
        Set<String> approved = copySet(state, APPROVED);
        Set<String> priorUnexpected = copySet(state, UNAPPROVED);
        Set<String> unexpected = PhoneGuardDecision.unexpected(approved, installed);

        Set<String> newlyUnexpected = new HashSet<>(unexpected);
        newlyUnexpected.removeAll(priorUnexpected);
        Set<String> alerted = copySet(state, ALERTED);
        alerted.retainAll(unexpected);

        for (String packageName : newlyUnexpected) {
            recordIncident(context, packageName);
        }

        int alertsPosted = 0;
        Set<String> pendingAlerts = PhoneGuardDecision.pendingAlerts(
                unexpected, alerted, MAX_ALERTS_PER_SCAN);
        for (String packageName : pendingAlerts) {
            PackageManager manager = context.getPackageManager();
            String label = applicationLabel(manager, packageName);
            InstallSourceEvidence.Source source = InstallSourceEvidence.read(manager, packageName);
            if (PhoneGuardNotifications.notifyUnexpectedApp(
                    context, label, packageName, source)) {
                alerted.add(packageName);
                alertsPosted++;
            }
        }

        state.edit()
                .putStringSet(UNAPPROVED, new HashSet<>(unexpected))
                .putStringSet(ALERTED, new HashSet<>(alerted))
                .apply();
        return new ScanResult(true, unexpected.size(), newlyUnexpected.size(), alertsPosted);
    }

    public static boolean approveLast(Context context) {
        String packageName = lastPackage(context);
        if (packageName.isEmpty() || !isInstalled(context.getPackageManager(), packageName)) {
            return false;
        }
        SharedPreferences state = preferences(context);
        Set<String> approved = copySet(state, APPROVED);
        Set<String> unapproved = copySet(state, UNAPPROVED);
        Set<String> alerted = copySet(state, ALERTED);
        approved.add(packageName);
        unapproved.remove(packageName);
        alerted.remove(packageName);
        state.edit()
                .putStringSet(APPROVED, approved)
                .putStringSet(UNAPPROVED, unapproved)
                .putStringSet(ALERTED, alerted)
                .apply();
        return true;
    }

    public static String lastPackage(Context context) {
        return preferences(context).getString(LAST_PACKAGE, "");
    }

    public static int unapprovedCount(Context context) {
        return copySet(preferences(context), UNAPPROVED).size();
    }

    public static String statusSummary(Context context) {
        if (!isArmed(context)) {
            return "DISARMED";
        }
        int count = unapprovedCount(context);
        String latest = preferences(context).getString(LAST_LABEL, "");
        String base = "ARMED — " + count + " unapproved app" + (count == 1 ? "" : "s");
        return latest == null || latest.isEmpty() ? base : base + "; latest: " + latest;
    }

    public static String latestIncidentJson(Context context) {
        SharedPreferences state = preferences(context);
        String packageName = state.getString(LAST_PACKAGE, "");
        if (packageName == null || packageName.isEmpty()) {
            return "";
        }
        return "{\n"
                + "  \"schema_version\": 1,\n"
                + "  \"evidence_kind\": \"phone_guard_owner_baseline_delta\",\n"
                + "  \"disposition\": \"UNAPPROVED\",\n"
                + "  \"package_name\": " + json(state.getString(LAST_PACKAGE, "")) + ",\n"
                + "  \"application_label\": " + json(state.getString(LAST_LABEL, "")) + ",\n"
                + "  \"installing_package\": " + json(state.getString(LAST_INSTALLER, "")) + ",\n"
                + "  \"initiating_package\": " + json(state.getString(LAST_INITIATOR, "")) + ",\n"
                + "  \"originating_package\": " + json(state.getString(LAST_ORIGINATOR, "")) + ",\n"
                + "  \"update_owner_package\": " + json(state.getString(LAST_UPDATE_OWNER, "")) + ",\n"
                + "  \"package_source\": " + json(state.getString(LAST_SOURCE_KIND, "")) + ",\n"
                + "  \"observed_at\": " + json(state.getString(LAST_OBSERVED_AT, "")) + ",\n"
                + "  \"claim_scope\": \"Installed package was not in the owner-approved baseline; this alone does not prove malware or unauthorized installer intent.\"\n"
                + "}\n";
    }

    private static void recordIncident(Context context, String packageName) {
        PackageManager manager = context.getPackageManager();
        InstallSourceEvidence.Source source = InstallSourceEvidence.read(manager, packageName);
        preferences(context).edit()
                .putString(LAST_PACKAGE, packageName)
                .putString(LAST_LABEL, applicationLabel(manager, packageName))
                .putString(LAST_INSTALLER, value(source.installingPackage))
                .putString(LAST_INITIATOR, value(source.initiatingPackage))
                .putString(LAST_ORIGINATOR, value(source.originatingPackage))
                .putString(LAST_UPDATE_OWNER, value(source.updateOwnerPackage))
                .putString(LAST_SOURCE_KIND, value(source.sourceKind))
                .putString(LAST_OBSERVED_AT, Instant.now().toString())
                .apply();
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    private static Set<String> copySet(SharedPreferences state, String key) {
        return new HashSet<>(state.getStringSet(key, Collections.emptySet()));
    }

    private static Set<String> installedPackageNames(PackageManager manager) {
        Set<String> names = new HashSet<>();
        try {
            List<PackageInfo> packages;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packages = manager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L));
            } else {
                packages = manager.getInstalledPackages(0);
            }
            for (PackageInfo info : packages) {
                if (info.packageName != null && !info.packageName.isEmpty()) {
                    names.add(info.packageName);
                }
            }
        } catch (SecurityException ignored) {
            // QUERY_ALL_PACKAGES is declared for this security sensor; fail closed to an empty read.
        }
        return names;
    }

    private static boolean isInstalled(PackageManager manager, String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                manager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L));
            } else {
                manager.getPackageInfo(packageName, 0);
            }
            return true;
        } catch (PackageManager.NameNotFoundException | SecurityException ignored) {
            return false;
        }
    }

    private static String applicationLabel(PackageManager manager, String packageName) {
        try {
            ApplicationInfo info;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                info = manager.getApplicationInfo(
                        packageName, PackageManager.ApplicationInfoFlags.of(0L));
            } else {
                info = manager.getApplicationInfo(packageName, 0);
            }
            CharSequence label = manager.getApplicationLabel(info);
            return label == null || label.length() == 0 ? packageName : label.toString();
        } catch (PackageManager.NameNotFoundException | SecurityException ignored) {
            return packageName;
        }
    }

    private static String value(String input) {
        return input == null ? "" : input;
    }

    private static String json(String input) {
        String value = input == null ? "" : input;
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }

    public static final class ScanResult {
        public final boolean armed;
        public final int unapprovedCount;
        public final int newFindings;
        public final int alertsPosted;

        private ScanResult(
                boolean armed,
                int unapprovedCount,
                int newFindings,
                int alertsPosted) {
            this.armed = armed;
            this.unapprovedCount = unapprovedCount;
            this.newFindings = newFindings;
            this.alertsPosted = alertsPosted;
        }

        static ScanResult disarmed() {
            return new ScanResult(false, 0, 0, 0);
        }

        public String summary() {
            if (!armed) {
                return "Phone Guard is disarmed.";
            }
            return "Phone Guard check complete: " + unapprovedCount
                    + " unapproved app" + (unapprovedCount == 1 ? "" : "s")
                    + ", " + newFindings + " new finding" + (newFindings == 1 ? "" : "s")
                    + ", " + alertsPosted + " alert" + (alertsPosted == 1 ? "" : "s")
                    + " posted.";
        }
    }
}
