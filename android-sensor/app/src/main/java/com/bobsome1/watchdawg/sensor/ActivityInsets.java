package com.bobsome1.watchdawg.sensor;

import android.graphics.Insets;
import android.os.Build;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;

/** Keeps scrollable controls inside the safe area when Android enforces edge-to-edge. */
final class ActivityInsets {
    private ActivityInsets() {}

    static void applyTo(View root, boolean lightBackground) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            return;
        }

        int left = root.getPaddingLeft();
        int top = root.getPaddingTop();
        int right = root.getPaddingRight();
        int bottom = root.getPaddingBottom();
        int insetTypes = WindowInsets.Type.systemBars()
                | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime();
        int lightBars = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;

        root.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets safeArea = insets.getInsets(insetTypes);
            view.setPadding(left + safeArea.left, top + safeArea.top,
                    right + safeArea.right, bottom + safeArea.bottom);
            WindowInsetsController controller = view.getWindowInsetsController();
            if (controller != null) {
                controller.setSystemBarsAppearance(lightBackground ? lightBars : 0, lightBars);
            }
            return insets;
        });
    }
}
