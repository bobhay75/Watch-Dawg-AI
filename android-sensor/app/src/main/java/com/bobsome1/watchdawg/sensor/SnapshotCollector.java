package com.bobsome1.watchdawg.sensor;

import android.Manifest;
import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.provider.Settings;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Collects evidence available to a normal, non-root Android security app. */
public final class SnapshotCollector {
    private static final String PREFERENCES = "watchdawg_collection_state";
    private static final String LAST_USAGE_SCAN = "last_usage_scan_ms";
    private static final String LAST_USAGE_SCAN_ORDINAL = "last_usage_scan_ordinal";
    private static final String USAGE_BASELINE_READY = "usage_baseline_ready";
    private static final String BASELINE_READY = "baseline_ready";
    private static final String SEEN_PACKAGES = "seen_packages";
    private static final String INVENTORY = "package_inventory";
    private static final String PERMISSION_STATE = "permission_state";
    private static final long FIRST_SCAN_WINDOW_MILLIS = 60L * 60L * 1000L;
    private static final long MAX_SCAN_WINDOW_MILLIS = 24L * 60L * 60L * 1000L;
    private static final int MAX_EVENTS = 500;

    private static final List<String> SENSITIVE_PERMISSIONS = Collections.unmodifiableList(
            Arrays.asList(
                    Manifest.permission.CAMERA,
                    Manifest.permission.RECORD_AUDIO,
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION,
                    Manifest.permission.READ_CONTACTS,
                    Manifest.permission.WRITE_CONTACTS,
                    Manifest.permission.READ_CALENDAR,
                    Manifest.permission.WRITE_CALENDAR,
                    Manifest.permission.READ_SMS,
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.SEND_SMS,
                    Manifest.permission.READ_PHONE_STATE,
                    Manifest.permission.CALL_PHONE,
                    "android.permission.POST_NOTIFICATIONS"));

    private SnapshotCollector() {}

    public static CollectionResult collect(Context context, long sequence) throws Exception {
        DeviceIdentity.ensureKey();
        long nowMillis = System.currentTimeMillis();
        SecurityPatchStatus securityPatch = SecurityPatchStatus.from(
                Build.VERSION.SECURITY_PATCH,
                Instant.ofEpochMilli(nowMillis).atZone(ZoneOffset.UTC).toLocalDate());
        SharedPreferences state = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
        boolean usageGranted = hasUsageAccess(context);

        List<Map<String, Object>> events = new ArrayList<>();
        InventoryResult inventory = collectInventory(
                context, state, events, nowMillis);
        Set<String> prunedSeenPackages = new HashSet<>(
                state.getStringSet(SEEN_PACKAGES, Collections.emptySet()));
        boolean seenPackagesPruned = prunedSeenPackages.removeAll(
                inventory.removedPackageHashes);
        UsageResult usage = UsageResult.notQueried(
                false, seenPackagesPruned ? prunedSeenPackages : null);
        if (usageGranted) {
            usage = events.size() < MAX_EVENTS
                    ? collectUsageEvents(
                            context, state, events, nowMillis, prunedSeenPackages)
                    : UsageResult.notQueried(
                            true, seenPackagesPruned ? prunedSeenPackages : null);
        }
        ConnectivityResult connectivity = connectivity(context);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("schema_version", 1L);
        payload.put("device_id", DeviceIdentity.deviceId());
        payload.put("sequence", sequence);
        payload.put("collected_at", Instant.ofEpochMilli(nowMillis).toString());
        payload.put("collector", collectorMetadata(
                context,
                usageGranted,
                usage.queryAvailable,
                !usage.truncated && !usage.historyGap,
                securityPatch));
        payload.put("sensors", sensorCoverage(
                usageGranted,
                usage.queryAvailable,
                !usage.truncated && !usage.historyGap,
                connectivity.queryAvailable));
        payload.put("posture", posture(context, securityPatch));
        payload.put("posture_evidence", postureEvidence(context, securityPatch));
        payload.put("permission_posture", inventory.permissionPosture);
        payload.put("connectivity", connectivity.evidence);
        payload.put("events", events);
        payload.put("collection", collectionMetadata(events, inventory, usage, usageGranted));

        Map<String, Object> mesh = new LinkedHashMap<>();
        mesh.put("enabled", false);
        mesh.put("peer_count", 0L);
        mesh.put("signed_updates_only", true);
        mesh.put("raw_data_sharing", false);
        payload.put("mesh", mesh);
        payload.put("actions_executed", false);
        List<String> limitations = new ArrayList<>(Arrays.asList(
                "No root, accessibility, VPN, camera, or microphone permission is used.",
                "Android public APIs do not expose other apps' live camera or microphone use to this app.",
                "Sensor-capability events mean a foreground app held a related permission; they do not prove sensor use.",
                "Connectivity evidence reports active transport metadata only, not destinations or content.",
                "Package identifiers are HMAC-pseudonymized on this device before export.",
                "A package signing certificate is mandatory Android packaging metadata and does not establish publisher trust."));
        if (inventory.packageDeltasTruncated
                || inventory.permissionDeltasTruncated
                || usage.truncated) {
            limitations.add(
                    "One or more event streams reached the per-snapshot limit; the signed collection metadata marks the partial coverage and checkpoints conservatively for retry.");
        }
        if (usage.historyGap) {
            limitations.add(
                    "UsageStats retention or clock movement left an unobserved history interval; this snapshot's process coverage is partial.");
        }
        payload.put("limitations", limitations);

        StateUpdate stateUpdate = new StateUpdate(
                state,
                inventory.currentInventory,
                inventory.currentPermissionState,
                usage.seenPackages,
                usage.lastUsageScan,
                usage.lastUsageScanOrdinal,
                usage.baselineReady);
        return new CollectionResult(payload, stateUpdate);
    }

    public static boolean hasUsageAccess(Context context) {
        AppOpsManager appOps = (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
        if (appOps == null) {
            return false;
        }
        int mode = appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                context.getPackageName());
        return mode == AppOpsManager.MODE_ALLOWED;
    }

    private static Map<String, Object> collectorMetadata(
            Context context,
            boolean usageGranted,
            boolean usageQueryAvailable,
            boolean usageQueryComplete,
            SecurityPatchStatus securityPatch) {
        Map<String, Object> collector = new LinkedHashMap<>();
        collector.put("platform", "android");
        collector.put("android_api", (long) Build.VERSION.SDK_INT);
        collector.put("security_patch", securityPatch.value);
        collector.put("signing_key_security", DeviceIdentity.keySecurityLevel());
        collector.put("usage_access", usageGranted ? "granted" : "not_granted");
        collector.put("usage_query_status", UsageSensorStatus.resolve(
                usageGranted, usageQueryAvailable, usageQueryComplete));
        collector.put("collection_mode", "non_root_public_api");
        try {
            PackageInfo ownPackage = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            collector.put("app_version", MetadataNormalizer.appVersion(
                    ownPackage.versionName));
        } catch (PackageManager.NameNotFoundException error) {
            collector.put("app_version", "unknown");
        }
        return collector;
    }

    private static Map<String, Object> sensorCoverage(
            boolean usageGranted,
            boolean usageQueryAvailable,
            boolean usageQueryComplete,
            boolean connectivityQueryAvailable) {
        Map<String, Object> sensors = new LinkedHashMap<>();
        sensors.put("camera", sensor(
                "unsupported",
                "android_public_api",
                "direct_cross_app_access"));
        sensors.put("microphone", sensor(
                "unsupported",
                "android_public_api",
                "direct_cross_app_access"));
        sensors.put("identity", sensor(
                "unsupported",
                "android_public_api",
                "device_authentication_events"));
        sensors.put("process", sensor(
                UsageSensorStatus.resolve(
                        usageGranted, usageQueryAvailable, usageQueryComplete),
                "android_usage_stats",
                "foreground_transitions"));
        sensors.put("network", sensor(
                connectivityQueryAvailable ? "observed" : "error",
                "android_connectivity",
                "active_transport_only"));
        return sensors;
    }

    private static Map<String, Object> sensor(String status, String source, String scope) {
        Map<String, Object> sensor = new LinkedHashMap<>();
        sensor.put("status", status);
        sensor.put("source", source);
        sensor.put("scope", scope);
        return sensor;
    }

    private static Map<String, Object> posture(
            Context context, SecurityPatchStatus securityPatch) {
        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("disk_encrypted", storageEncrypted(context));
        KeyguardManager keyguard = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        posture.put("screen_lock", keyguard != null && keyguard.isDeviceSecure());
        posture.put("security_updates_current", securityPatch.isCurrent(120L));
        return posture;
    }

    private static Map<String, Object> collectionMetadata(
            List<Map<String, Object>> events,
            InventoryResult inventory,
            UsageResult usage,
            boolean usageGranted) {
        boolean complete = !inventory.packageDeltasTruncated
                && !inventory.permissionDeltasTruncated
                && !usage.truncated
                && !usage.historyGap
                && (!usageGranted || usage.queryAvailable);
        Map<String, Object> collection = new LinkedHashMap<>();
        collection.put("event_limit", (long) MAX_EVENTS);
        collection.put("events_emitted", (long) events.size());
        collection.put("complete", complete);
        collection.put("package_deltas_truncated", inventory.packageDeltasTruncated);
        collection.put("permission_deltas_truncated", inventory.permissionDeltasTruncated);
        collection.put("usage_events_truncated", usage.truncated);
        collection.put("usage_query_available", usage.queryAvailable);
        collection.put("usage_history_gap", usage.historyGap);
        return collection;
    }

    private static Map<String, Object> postureEvidence(
            Context context, SecurityPatchStatus securityPatch) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("disk_encryption_status", storageEncryptionStatus(context));
        evidence.put("secure_boot", sensor(
                "unsupported", "android_public_api", "verified_boot_state"));
        evidence.put("security_patch", securityPatch.value);
        evidence.put("security_patch_age_days", securityPatch.ageDays);
        evidence.put("security_patch_policy_max_age_days", 120L);
        evidence.put("developer_options", readGlobalSetting(
                context, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED));
        evidence.put("adb_enabled", readGlobalSetting(context, Settings.Global.ADB_ENABLED));
        return evidence;
    }

    private static boolean storageEncrypted(Context context) {
        int status = storageEncryptionStatusCode(context);
        return status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
                || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER;
    }

    private static int storageEncryptionStatusCode(Context context) {
        try {
            DevicePolicyManager manager = (DevicePolicyManager) context.getSystemService(
                    Context.DEVICE_POLICY_SERVICE);
            return manager == null
                    ? DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED
                    : manager.getStorageEncryptionStatus();
        } catch (SecurityException error) {
            return DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED;
        }
    }

    private static String storageEncryptionStatus(Context context) {
        switch (storageEncryptionStatusCode(context)) {
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE:
                return "active";
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY:
                return "active_default_key";
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER:
                return "active_per_user";
            case DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE:
                return "inactive";
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING:
                return "activating";
            case DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED:
            default:
                return "unsupported_or_unavailable";
        }
    }

    private static String readGlobalSetting(Context context, String name) {
        try {
            return Settings.Global.getInt(context.getContentResolver(), name, 0) == 1
                    ? "enabled" : "disabled";
        } catch (SecurityException error) {
            return "unavailable";
        }
    }

    private static ConnectivityResult connectivity(Context context) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scope", "active_transport_only");
        result.put("destinations_observed", false);
        result.put("content_observed", false);
        List<String> transports = new ArrayList<>();
        boolean queryAvailable = true;
        try {
            ConnectivityManager manager = (ConnectivityManager) context.getSystemService(
                    Context.CONNECTIVITY_SERVICE);
            if (manager == null) {
                queryAvailable = false;
                result.put("error", "service_unavailable");
            } else {
                Network network = manager.getActiveNetwork();
                NetworkCapabilities capabilities = network == null
                        ? null : manager.getNetworkCapabilities(network);
                if (capabilities != null) {
                addTransport(capabilities, NetworkCapabilities.TRANSPORT_WIFI, "wifi", transports);
                addTransport(capabilities, NetworkCapabilities.TRANSPORT_CELLULAR, "cellular", transports);
                addTransport(capabilities, NetworkCapabilities.TRANSPORT_ETHERNET, "ethernet", transports);
                addTransport(capabilities, NetworkCapabilities.TRANSPORT_VPN, "vpn", transports);
                addTransport(capabilities, NetworkCapabilities.TRANSPORT_BLUETOOTH, "bluetooth", transports);
                result.put("validated", capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED));
                result.put("captive_portal", capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL));
                result.put("metered", !capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_NOT_METERED));
                } else {
                    result.put("validated", false);
                    result.put("captive_portal", false);
                    result.put("metered", false);
                }
            }
        } catch (SecurityException error) {
            queryAvailable = false;
            result.put("error", "permission_unavailable");
        }
        result.put("transports", transports);
        return new ConnectivityResult(result, queryAvailable);
    }

    private static void addTransport(
            NetworkCapabilities capabilities,
            int transport,
            String name,
            List<String> output) {
        if (capabilities.hasTransport(transport)) {
            output.add(name);
        }
    }

    private static InventoryResult collectInventory(
            Context context,
            SharedPreferences state,
            List<Map<String, Object>> events,
            long observedAtMillis) throws Exception {
        PackageManager manager = context.getPackageManager();
        List<PackageInfo> packages;
        long flags = PackageManager.GET_PERMISSIONS;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packages = manager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags));
        } else {
            packages = manager.getInstalledPackages((int) flags);
        }

        Set<String> priorInventory = new HashSet<>(
                state.getStringSet(INVENTORY, Collections.emptySet()));
        Set<String> priorPermissionState = new HashSet<>(
                state.getStringSet(PERMISSION_STATE, Collections.emptySet()));
        Map<String, String> priorInventoryByPackage =
                CollectionStateIndex.inventory(priorInventory);
        CollectionStateIndex.PermissionIndex priorPermissions =
                CollectionStateIndex.permissions(priorPermissionState);
        boolean baselineReady = state.getBoolean(BASELINE_READY, false);
        Set<String> currentInventory = new HashSet<>();
        Set<String> currentPermissionState = new HashSet<>();
        Set<String> observedPackageHashes = new HashSet<>();
        Set<String> removedPackageHashes = new HashSet<>();
        Map<String, Long> permissionCounts = new LinkedHashMap<>();
        boolean packageDeltasTruncated = false;
        boolean permissionDeltasTruncated = false;
        for (String permission : SENSITIVE_PERMISSIONS) {
            permissionCounts.put(shortPermission(permission), 0L);
        }

        for (PackageInfo packageInfo : packages) {
            String packageHash = PackageHasher.hash(packageInfo.packageName);
            observedPackageHashes.add(packageHash);
            long version = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                    ? packageInfo.getLongVersionCode() : packageInfo.versionCode;
            String inventoryEntry = packageHash + "|" + version;
            String priorEntry = priorInventoryByPackage.get(packageHash);
            boolean hasCertificate = hasSigningCertificate(packageInfo);
            boolean packageDeltaRequired = baselineReady
                    && !inventoryEntry.equals(priorEntry);
            boolean packageDeltaEmitted = false;
            if (packageDeltaRequired && events.size() < MAX_EVENTS) {
                if (priorEntry == null) {
                    events.add(packageEvent(
                            "package_added",
                            packageHash,
                            hasCertificate,
                            observedAtMillis));
                } else {
                    events.add(packageEvent(
                            "package_updated",
                            packageHash,
                            hasCertificate,
                            observedAtMillis));
                }
                packageDeltaEmitted = true;
            }
            String inventoryCheckpoint = DeltaCheckpoint.select(
                    priorEntry,
                    inventoryEntry,
                    packageDeltaRequired,
                    packageDeltaEmitted);
            if (inventoryCheckpoint != null) {
                currentInventory.add(inventoryCheckpoint);
            }
            boolean packageCheckpointed = inventoryEntry.equals(inventoryCheckpoint);
            if (packageDeltaRequired && !packageDeltaEmitted) {
                packageDeltasTruncated = true;
            }

            for (String permission : SENSITIVE_PERMISSIONS) {
                boolean granted = manager.checkPermission(permission, packageInfo.packageName)
                        == PackageManager.PERMISSION_GRANTED;
                String permissionEntry = packageHash + "|" + shortPermission(permission)
                        + "|" + (granted ? "1" : "0");
                if (granted) {
                    String shortName = shortPermission(permission);
                    permissionCounts.put(shortName, permissionCounts.get(shortName) + 1L);
                }

                String priorPermissionEntry = priorPermissions.get(
                        packageHash, shortPermission(permission));
                boolean permissionDeltaRequired = baselineReady
                        && priorPermissionEntry != null
                        && !priorPermissionEntry.equals(permissionEntry);
                boolean permissionDeltaEmitted = false;
                if (packageCheckpointed
                        && permissionDeltaRequired
                        && events.size() < MAX_EVENTS) {
                    events.add(permissionEvent(
                            packageHash,
                            shortPermission(permission),
                            granted,
                            hasCertificate,
                            observedAtMillis));
                    permissionDeltaEmitted = true;
                }
                String permissionCheckpoint = DeltaCheckpoint.select(
                        priorPermissionEntry,
                        permissionEntry,
                        !packageCheckpointed || permissionDeltaRequired,
                        permissionDeltaEmitted);
                if (permissionCheckpoint != null) {
                    currentPermissionState.add(permissionCheckpoint);
                }
                if (permissionDeltaRequired && !permissionDeltaEmitted) {
                    permissionDeltasTruncated = true;
                }
            }
        }

        if (baselineReady) {
            for (Map.Entry<String, String> priorPackage
                    : priorInventoryByPackage.entrySet()) {
                String priorHash = priorPackage.getKey();
                if (observedPackageHashes.contains(priorHash)) {
                    continue;
                }
                removedPackageHashes.add(priorHash);
                if (events.size() < MAX_EVENTS) {
                    events.add(packageEvent(
                            "package_removed", priorHash, false, observedAtMillis));
                } else {
                    packageDeltasTruncated = true;
                    currentInventory.add(priorPackage.getValue());
                    currentPermissionState.addAll(
                            priorPermissions.forPackage(priorHash));
                }
            }
        }

        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("inventory_scope", "installed_packages_visible_to_security_app");
        posture.put("package_identifiers", "device_keyed_hmac_sha256");
        posture.put("packages_observed", (long) packages.size());
        posture.put("granted_sensitive_permission_counts", permissionCounts);
        posture.put("baseline_initialized", baselineReady);
        return new InventoryResult(
                posture,
                currentInventory,
                currentPermissionState,
                packageDeltasTruncated,
                permissionDeltasTruncated,
                removedPackageHashes);
    }

    private static UsageResult collectUsageEvents(
            Context context,
            SharedPreferences state,
            List<Map<String, Object>> events,
            long nowMillis,
            Set<String> initialSeenPackages) throws Exception {
        long lastScan = state.getLong(LAST_USAGE_SCAN, 0L);
        long lastScanOrdinal = state.getLong(LAST_USAGE_SCAN_ORDINAL, 0L);
        UsageQueryWindow queryWindow = UsageQueryWindow.resolve(
                state.contains(LAST_USAGE_SCAN),
                lastScan,
                nowMillis,
                FIRST_SCAN_WINDOW_MILLIS,
                MAX_SCAN_WINDOW_MILLIS);
        long start = queryWindow.startMillis;
        UsageStatsManager usageStats = (UsageStatsManager) context.getSystemService(
                Context.USAGE_STATS_SERVICE);
        if (usageStats == null) {
            return UsageResult.notQueried(
                    false, queryWindow.historyGap, initialSeenPackages);
        }

        Set<String> seen = new HashSet<>(initialSeenPackages);
        boolean hadSeenBaseline = UsageBaseline.wasReady(
                state.contains(USAGE_BASELINE_READY),
                state.getBoolean(USAGE_BASELINE_READY, false),
                state.contains(LAST_USAGE_SCAN));
        Map<String, PackageInfo> packageCache = new HashMap<>();
        UsageEvents usageEvents = usageStats.queryEvents(start, nowMillis);
        if (usageEvents == null) {
            return UsageResult.notQueried(
                    false, queryWindow.historyGap, initialSeenPackages);
        }
        UsageEvents.Event usageEvent = new UsageEvents.Event();
        UsageCheckpoint checkpoint = queryWindow.historyGap
                ? UsageCheckpoint.restore(start, 0L)
                : UsageCheckpoint.restore(lastScan, lastScanOrdinal);
        long sourceTimestamp = Long.MIN_VALUE;
        long sourceOrdinal = 0L;
        boolean truncated = false;
        while (usageEvents.hasNextEvent()) {
            if (events.size() >= MAX_EVENTS) {
                truncated = true;
                break;
            }
            usageEvents.getNextEvent(usageEvent);
            long eventTimestamp = usageEvent.getTimeStamp();
            if (eventTimestamp == sourceTimestamp) {
                sourceOrdinal++;
            } else {
                sourceTimestamp = eventTimestamp;
                sourceOrdinal = 1L;
            }
            if (checkpoint.wasConsumed(eventTimestamp, sourceOrdinal)) {
                continue;
            }
            if (!isForegroundTransition(usageEvent.getEventType())) {
                checkpoint = checkpoint.afterConsumed(eventTimestamp, sourceOrdinal);
                continue;
            }
            String packageName = usageEvent.getPackageName();
            if (packageName == null || packageName.isEmpty()) {
                checkpoint = checkpoint.afterConsumed(eventTimestamp, sourceOrdinal);
                continue;
            }
            PackageInfo packageInfo = packageCache.get(packageName);
            if (packageInfo == null) {
                try {
                    packageInfo = packageInfoWithPermissions(context.getPackageManager(), packageName);
                    packageCache.put(packageName, packageInfo);
                } catch (PackageManager.NameNotFoundException ignored) {
                    checkpoint = checkpoint.afterConsumed(eventTimestamp, sourceOrdinal);
                    continue;
                }
            }
            String packageHash = PackageHasher.hash(packageName);
            String baseline = seen.contains(packageHash)
                    ? "known"
                    : (hadSeenBaseline ? "unexpected" : "initializing");
            boolean hasCertificate = hasSigningCertificate(packageInfo);
            if (hasGrantedPermission(context, packageName, Manifest.permission.CAMERA)) {
                events.add(capabilityEvent(
                        "camera_capable_foreground",
                        packageHash,
                        hasCertificate,
                        baseline,
                        eventTimestamp));
            }
            if (hasGrantedPermission(
                    context, packageName, Manifest.permission.RECORD_AUDIO)) {
                if (events.size() < MAX_EVENTS) {
                    events.add(capabilityEvent(
                            "microphone_capable_foreground",
                            packageHash,
                            hasCertificate,
                            baseline,
                            eventTimestamp));
                } else {
                    // Replay from this timestamp. This can duplicate the camera event,
                    // but it cannot silently skip the unread microphone evidence.
                    truncated = true;
                    break;
                }
            }
            seen.add(packageHash);
            checkpoint = checkpoint.afterConsumed(eventTimestamp, sourceOrdinal);
        }
        checkpoint = checkpoint.afterQuery(nowMillis, truncated);
        return new UsageResult(
                seen,
                checkpoint.timestamp,
                checkpoint.ordinal,
                true,
                truncated,
                queryWindow.historyGap,
                UsageBaseline.afterQuery(
                        hadSeenBaseline, !truncated, queryWindow.historyGap));
    }

    private static PackageInfo packageInfoWithPermissions(PackageManager manager, String packageName)
            throws PackageManager.NameNotFoundException {
        long flags = PackageManager.GET_PERMISSIONS;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return manager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags));
        }
        return manager.getPackageInfo(packageName, (int) flags);
    }

    private static boolean isForegroundTransition(int eventType) {
        if (eventType == UsageEvents.Event.MOVE_TO_FOREGROUND) {
            return true;
        }
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                && eventType == UsageEvents.Event.ACTIVITY_RESUMED;
    }

    private static boolean hasGrantedPermission(
            Context context, String packageName, String permission) {
        return context.getPackageManager().checkPermission(permission, packageName)
                == PackageManager.PERMISSION_GRANTED;
    }

    private static boolean hasSigningCertificate(PackageInfo packageInfo) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return packageInfo.signingInfo != null
                    && (packageInfo.signingInfo.hasMultipleSigners()
                    ? packageInfo.signingInfo.getApkContentsSigners().length > 0
                    : packageInfo.signingInfo.getSigningCertificateHistory().length > 0);
        }
        return packageInfo.signatures != null && packageInfo.signatures.length > 0;
    }

    private static Map<String, Object> capabilityEvent(
            String type,
            String packageHash,
            boolean hasSigningCertificate,
            String baseline,
            long observedAtMillis) {
        Map<String, Object> event = commonEvent(
                type, packageHash, hasSigningCertificate, baseline);
        event.put("sensitive", true);
        event.put("evidence_kind", "capability_inference");
        event.put("observed_at", Instant.ofEpochMilli(observedAtMillis).toString());
        event.put("claim", "foreground_transition_plus_granted_permission_not_sensor_use");
        return event;
    }

    private static Map<String, Object> packageEvent(
            String type,
            String packageHash,
            boolean hasSigningCertificate,
            long observedAtMillis) {
        Map<String, Object> event = commonEvent(
                type, packageHash, hasSigningCertificate, "unexpected");
        event.put("sensitive", false);
        event.put("evidence_kind", "package_inventory_delta");
        event.put("observed_at", Instant.ofEpochMilli(observedAtMillis).toString());
        return event;
    }

    private static Map<String, Object> permissionEvent(
            String packageHash,
            String permission,
            boolean granted,
            boolean hasSigningCertificate,
            long observedAtMillis) {
        Map<String, Object> event = commonEvent(
                "permission_change",
                packageHash,
                hasSigningCertificate,
                "unexpected");
        event.put("sensitive", true);
        event.put("evidence_kind", "permission_inventory_delta");
        event.put("permission", permission);
        event.put("granted", granted);
        event.put("observed_at", Instant.ofEpochMilli(observedAtMillis).toString());
        return event;
    }

    private static Map<String, Object> commonEvent(
            String type,
            String packageHash,
            boolean hasSigningCertificate,
            String baseline) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("type", type);
        event.put("process", packageHash);
        event.put("package_has_signing_certificate", hasSigningCertificate);
        event.put("baseline", baseline);
        event.put("bytes_out", 0L);
        event.put("destination", "");
        return event;
    }

    private static String shortPermission(String permission) {
        int separator = permission.lastIndexOf('.');
        return separator >= 0 ? permission.substring(separator + 1) : permission;
    }

    public static final class CollectionResult {
        private final Map<String, Object> payload;
        private final StateUpdate stateUpdate;

        private CollectionResult(Map<String, Object> payload, StateUpdate stateUpdate) {
            this.payload = payload;
            this.stateUpdate = stateUpdate;
        }

        public Map<String, Object> payload() {
            return payload;
        }

        void commitState() {
            stateUpdate.commit();
        }
    }

    private static final class ConnectivityResult {
        private final Map<String, Object> evidence;
        private final boolean queryAvailable;

        private ConnectivityResult(
                Map<String, Object> evidence, boolean queryAvailable) {
            this.evidence = evidence;
            this.queryAvailable = queryAvailable;
        }
    }

    private static final class InventoryResult {
        private final Map<String, Object> permissionPosture;
        private final Set<String> currentInventory;
        private final Set<String> currentPermissionState;
        private final boolean packageDeltasTruncated;
        private final boolean permissionDeltasTruncated;
        private final Set<String> removedPackageHashes;

        private InventoryResult(
                Map<String, Object> permissionPosture,
                Set<String> currentInventory,
                Set<String> currentPermissionState,
                boolean packageDeltasTruncated,
                boolean permissionDeltasTruncated,
                Set<String> removedPackageHashes) {
            this.permissionPosture = permissionPosture;
            this.currentInventory = new HashSet<>(currentInventory);
            this.currentPermissionState = new HashSet<>(currentPermissionState);
            this.packageDeltasTruncated = packageDeltasTruncated;
            this.permissionDeltasTruncated = permissionDeltasTruncated;
            this.removedPackageHashes = new HashSet<>(removedPackageHashes);
        }
    }

    private static final class UsageResult {
        private final Set<String> seenPackages;
        private final Long lastUsageScan;
        private final Long lastUsageScanOrdinal;
        private final boolean queryAvailable;
        private final boolean truncated;
        private final boolean historyGap;
        private final Boolean baselineReady;

        private UsageResult(
                Set<String> seenPackages,
                long lastUsageScan,
                long lastUsageScanOrdinal,
                boolean queryAvailable,
                boolean truncated,
                boolean historyGap,
                boolean baselineReady) {
            this.seenPackages = new HashSet<>(seenPackages);
            this.lastUsageScan = lastUsageScan;
            this.lastUsageScanOrdinal = lastUsageScanOrdinal;
            this.queryAvailable = queryAvailable;
            this.truncated = truncated;
            this.historyGap = historyGap;
            this.baselineReady = baselineReady;
        }

        private UsageResult(
                boolean truncated,
                boolean historyGap,
                Set<String> seenPackages) {
            this.seenPackages = seenPackages == null
                    ? null : new HashSet<>(seenPackages);
            this.lastUsageScan = null;
            this.lastUsageScanOrdinal = null;
            this.queryAvailable = false;
            this.truncated = truncated;
            this.historyGap = historyGap;
            this.baselineReady = null;
        }

        private static UsageResult notQueried(
                boolean truncated, Set<String> seenPackages) {
            return notQueried(truncated, false, seenPackages);
        }

        private static UsageResult notQueried(
                boolean truncated,
                boolean historyGap,
                Set<String> seenPackages) {
            return new UsageResult(truncated, historyGap, seenPackages);
        }
    }

    /** A single deferred checkpoint applied only after the signed snapshot is durable. */
    private static final class StateUpdate {
        private final SharedPreferences preferences;
        private final Set<String> inventory;
        private final Set<String> permissionState;
        private final Set<String> seenPackages;
        private final Long lastUsageScan;
        private final Long lastUsageScanOrdinal;
        private final Boolean usageBaselineReady;

        private final boolean hadInventory;
        private final Set<String> priorInventory;
        private final boolean hadPermissionState;
        private final Set<String> priorPermissionState;
        private final boolean hadBaselineReady;
        private final boolean priorBaselineReady;
        private final boolean hadSeenPackages;
        private final Set<String> priorSeenPackages;
        private final boolean hadLastUsageScan;
        private final long priorLastUsageScan;
        private final boolean hadLastUsageScanOrdinal;
        private final long priorLastUsageScanOrdinal;
        private final boolean hadUsageBaselineReady;
        private final boolean priorUsageBaselineReady;

        private boolean committed;

        private StateUpdate(
                SharedPreferences preferences,
                Set<String> inventory,
                Set<String> permissionState,
                Set<String> seenPackages,
                Long lastUsageScan,
                Long lastUsageScanOrdinal,
                Boolean usageBaselineReady) {
            this.preferences = preferences;
            this.inventory = new HashSet<>(inventory);
            this.permissionState = new HashSet<>(permissionState);
            this.seenPackages = seenPackages == null ? null : new HashSet<>(seenPackages);
            this.lastUsageScan = lastUsageScan;
            this.lastUsageScanOrdinal = lastUsageScanOrdinal;
            this.usageBaselineReady = usageBaselineReady;

            hadInventory = preferences.contains(INVENTORY);
            priorInventory = new HashSet<>(
                    preferences.getStringSet(INVENTORY, Collections.emptySet()));
            hadPermissionState = preferences.contains(PERMISSION_STATE);
            priorPermissionState = new HashSet<>(
                    preferences.getStringSet(PERMISSION_STATE, Collections.emptySet()));
            hadBaselineReady = preferences.contains(BASELINE_READY);
            priorBaselineReady = preferences.getBoolean(BASELINE_READY, false);
            hadSeenPackages = preferences.contains(SEEN_PACKAGES);
            priorSeenPackages = new HashSet<>(
                    preferences.getStringSet(SEEN_PACKAGES, Collections.emptySet()));
            hadLastUsageScan = preferences.contains(LAST_USAGE_SCAN);
            priorLastUsageScan = preferences.getLong(LAST_USAGE_SCAN, 0L);
            hadLastUsageScanOrdinal = preferences.contains(LAST_USAGE_SCAN_ORDINAL);
            priorLastUsageScanOrdinal = preferences.getLong(
                    LAST_USAGE_SCAN_ORDINAL, 0L);
            hadUsageBaselineReady = preferences.contains(USAGE_BASELINE_READY);
            priorUsageBaselineReady = preferences.getBoolean(
                    USAGE_BASELINE_READY, false);
        }

        private synchronized void commit() {
            if (committed) {
                return;
            }
            SharedPreferences.Editor editor = preferences.edit()
                    .putStringSet(INVENTORY, new HashSet<>(inventory))
                    .putStringSet(PERMISSION_STATE, new HashSet<>(permissionState))
                    .putBoolean(BASELINE_READY, true);
            if (seenPackages != null) {
                editor.putStringSet(SEEN_PACKAGES, new HashSet<>(seenPackages));
            }
            if (lastUsageScan != null) {
                editor.putLong(LAST_USAGE_SCAN, lastUsageScan);
                editor.putLong(LAST_USAGE_SCAN_ORDINAL, lastUsageScanOrdinal);
            }
            if (usageBaselineReady != null) {
                editor.putBoolean(USAGE_BASELINE_READY, usageBaselineReady);
            }
            if (!editor.commit()) {
                restorePriorState();
                throw new IllegalStateException(
                        "Signed snapshot was saved, but its collection checkpoint could not be persisted; retry may duplicate evidence");
            }
            committed = true;
        }

        private void restorePriorState() {
            SharedPreferences.Editor rollback = preferences.edit();
            restoreStringSet(rollback, INVENTORY, hadInventory, priorInventory);
            restoreStringSet(
                    rollback, PERMISSION_STATE, hadPermissionState, priorPermissionState);
            if (hadBaselineReady) {
                rollback.putBoolean(BASELINE_READY, priorBaselineReady);
            } else {
                rollback.remove(BASELINE_READY);
            }
            if (seenPackages != null) {
                restoreStringSet(
                        rollback, SEEN_PACKAGES, hadSeenPackages, priorSeenPackages);
            }
            if (lastUsageScan != null) {
                if (hadLastUsageScan) {
                    rollback.putLong(LAST_USAGE_SCAN, priorLastUsageScan);
                } else {
                    rollback.remove(LAST_USAGE_SCAN);
                }
                if (hadLastUsageScanOrdinal) {
                    rollback.putLong(
                            LAST_USAGE_SCAN_ORDINAL, priorLastUsageScanOrdinal);
                } else {
                    rollback.remove(LAST_USAGE_SCAN_ORDINAL);
                }
            }
            if (usageBaselineReady != null) {
                if (hadUsageBaselineReady) {
                    rollback.putBoolean(
                            USAGE_BASELINE_READY, priorUsageBaselineReady);
                } else {
                    rollback.remove(USAGE_BASELINE_READY);
                }
            }
            // commit() updates the in-memory map before reporting disk success. Calling it here
            // restores the prior in-process view even if storage remains unavailable.
            rollback.commit();
        }

        private static void restoreStringSet(
                SharedPreferences.Editor editor,
                String key,
                boolean existed,
                Set<String> previous) {
            if (existed) {
                editor.putStringSet(key, new HashSet<>(previous));
            } else {
                editor.remove(key);
            }
        }
    }
}
