package com.bobsome1.watchdawg.sensor;

import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.os.Build;

/** Best-effort installer attribution exposed by Android public APIs. */
final class InstallSourceEvidence {
    private InstallSourceEvidence() {}

    static Source read(PackageManager manager, String packageName) {
        String installing = null;
        String initiating = null;
        String originating = null;
        String updateOwner = null;
        String sourceKind = "unavailable";
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo info = manager.getInstallSourceInfo(packageName);
                installing = info.getInstallingPackageName();
                initiating = info.getInitiatingPackageName();
                // Android normally withholds this from non-installer apps. Keep null honest.
                originating = info.getOriginatingPackageName();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    sourceKind = sourceKind(info.getPackageSource());
                } else {
                    sourceKind = "api_30_32_no_source_kind";
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    updateOwner = info.getUpdateOwnerPackageName();
                }
            } else {
                installing = manager.getInstallerPackageName(packageName);
                sourceKind = installing == null ? "unknown" : "installer_of_record";
            }
        } catch (PackageManager.NameNotFoundException | IllegalArgumentException
                 | SecurityException ignored) {
            sourceKind = "unavailable";
        }
        return new Source(installing, initiating, originating, updateOwner, sourceKind);
    }

    private static String sourceKind(int source) {
        switch (source) {
            case PackageInstaller.PACKAGE_SOURCE_STORE:
                return "store";
            case PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE:
                return "local_file";
            case PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE:
                return "downloaded_file";
            case PackageInstaller.PACKAGE_SOURCE_OTHER:
                return "other";
            case PackageInstaller.PACKAGE_SOURCE_UNSPECIFIED:
            default:
                return "unspecified";
        }
    }

    static final class Source {
        final String installingPackage;
        final String initiatingPackage;
        final String originatingPackage;
        final String updateOwnerPackage;
        final String sourceKind;

        Source(
                String installingPackage,
                String initiatingPackage,
                String originatingPackage,
                String updateOwnerPackage,
                String sourceKind) {
            this.installingPackage = installingPackage;
            this.initiatingPackage = initiatingPackage;
            this.originatingPackage = originatingPackage;
            this.updateOwnerPackage = updateOwnerPackage;
            this.sourceKind = sourceKind;
        }

        String bestInstaller() {
            if (initiatingPackage != null && !initiatingPackage.isEmpty()) {
                return initiatingPackage;
            }
            if (installingPackage != null && !installingPackage.isEmpty()) {
                return installingPackage;
            }
            return "unknown";
        }
    }
}
