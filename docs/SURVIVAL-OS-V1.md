# Watch-Dawg Survival OS V1

An Android activity inside the existing Watch-Dawg Sensor app. This is an app feature, not a replacement Android operating system.

## Device fit

Motorola lists the US moto g power (2025) with 8 GB physical RAM, 128 GB built-in storage, a MediaTek Dimensity 6300 octa-core CPU, and Android 15 at launch. Motorola's RAM Boost is virtual memory and is not counted as physical RAM. The app reads Android's reported RAM, currently available RAM, free app storage, Android release, API level, and 64-bit ABI at runtime. A model load is stopped when reported free memory is below 900 MB. CPU inference avoids depending on Mali GPU delegate support; actual speed and thermal behavior still require a phone test.

Sources:

- [Motorola moto g power (2025) specifications](https://en-us.support.motorola.com/app/answers/detail/a_id/184283/p/30%2C670%2C5511%2C)
- [Motorola software update information](https://en-us.support.motorola.com/app/software-security-update/g_id/7112/productid/12162/)
- [Google LiteRT-LM Kotlin API](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/api/kotlin/getting_started.md)

The exact retail/RAM variant and installed OS version of the user's handset have not been read from the device. Survival OS shows those runtime values on its screen when installed.

## Included in this implementation

- Native offline field guides: emergency kit, water, first aid, severe weather, power outages, and basic navigation.
- GPS coordinates on an explicit tap, using Android's GPS provider. Permission is requested only when used. GPS reception can fail indoors or without a clear sky view; this screen does not contain maps or route guidance.
- Private app-storage notes, plus user-directed export through Android's file picker. Notes are not included in the optional Watch-Dawg sensor sync.
- Import and local CPU inference for one .litertlm model. The model is kept in private app storage and the conversation stays in memory only.
- Clear buttons for stopping/removing the model and clearing the current chat.
- No model, guide, or chat request needs a network. The existing parent Sensor app retains its separate, manual HTTPS sync capability; that sensor feature is not required by Survival OS.

## Get the model

Recommended starter: **Qwen3 0.6B in LiteRT-LM format**. It is deliberately small for an 8 GB phone; it will be less capable than a larger desktop model. Use the CPU version so this implementation does not depend on GPU support.

1. While online, open the [LiteRT Community Qwen3 0.6B model repository](https://huggingface.co/litert-community/Qwen3-0.6B).
2. Read the model card and license. Download the .litertlm model file named Qwen3-0.6B.litertlm if that file is offered in the repository. Keep at least 1 GB free in internal phone storage for the imported model and runtime cache. Model repository contents can change; check the current file list.
3. Install and open Watch-Dawg Sensor, choose **Open Survival OS V1**, then **Import .litertlm model file** and select the file through Android's picker.
4. Wait for the import to finish, then choose **Load local model**. Loading and first inference may take time. Close other apps if the app reports less than 900 MB currently available.
5. Verify offline operation by enabling Airplane mode, turning Wi-Fi back off if Android enables it, and asking a simple test question. This test is for the user to perform on the handset; no handset is connected to this build session.

LiteRT-LM is pinned to version 0.18.1; the model is not bundled in the APK. The Google AI Edge project documents the Kotlin API and model distribution via Hugging Face. Model use is subject to its publisher's license.

## Build and install

From android-sensor/ with JDK 17, Android SDK 35, Gradle 8.9, and network access for Gradle dependencies:

    gradle --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug

The review APK, when assembly succeeds, is android-sensor/app/build/outputs/apk/debug/app-debug.apk. Install only after review:

    adb install -r app/build/outputs/apk/debug/app-debug.apk

The APK uses the debug signing key and is for review/testing only. No production signing or Play release is configured.

## Boundaries

Implemented: static references, private notes, user-triggered GPS, model import, CPU model loading, and offline chat code.

Not implemented: autonomous emergency calls, live weather/fire alerts, offline maps, satellite messaging, radio operation, medical diagnosis, background AI, network firewalling, or a full launcher/operating-system replacement. Small language-model output can be wrong; verify life-safety instructions with official local guidance. Emergency calls may not work without carrier service.
