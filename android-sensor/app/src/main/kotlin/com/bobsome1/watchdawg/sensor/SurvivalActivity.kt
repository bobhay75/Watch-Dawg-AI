package com.bobsome1.watchdawg.sensor

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.StatFs
import android.provider.Settings
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Contents
import com.google.ai.edge.litertlm.Conversation
import com.google.ai.edge.litertlm.ConversationConfig
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import com.google.ai.edge.litertlm.Role
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.Date
import java.util.Locale

/** User-directed field references and local-only model chat. */
class SurvivalActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val handler = Handler(Looper.getMainLooper())
    private var engine: Engine? = null
    private var conversation: Conversation? = null
    private var busy = false
    private var locationListener: LocationListener? = null
    private lateinit var status: TextView
    private lateinit var guide: TextView
    private lateinit var chatLog: TextView
    private lateinit var question: EditText
    private lateinit var notes: EditText
    private val modelFile get() = File(filesDir, MODEL_FILE)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(buildUi())
        notes.setText(getPreferences(MODE_PRIVATE).getString(NOTES_KEY, "").orEmpty())
        guide.text = GUIDES["kit"]
        status.text = deviceStatus()
    }

    override fun onDestroy() {
        locationListener?.let { (getSystemService(LOCATION_SERVICE) as LocationManager).removeUpdates(it) }
        scope.cancel()
        conversation?.close()
        engine?.close()
        super.onDestroy()
    }

    private fun buildUi(): ScrollView {
        val page = ScrollView(this).apply { setBackgroundColor(0xff101b1a.toInt()) }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(28))
        }
        page.addView(content)
        content.addView(label("WATCH-DAWG / SURVIVAL", 25f, 0xffe9f3eb.toInt(), true))
        content.addView(label(
            "Offline field references, private notes, GPS coordinates, and optional local AI.",
            15f, 0xffc5d4c8.toInt()
        ))
        status = cardText()
        content.addView(status)

        content.addView(section("FIELD GUIDE"))
        listOf(
            "72-hour kit" to "kit", "Water safety" to "water", "First aid" to "firstaid",
            "Severe weather" to "weather", "Power outage" to "power", "Navigation" to "navigation"
        ).forEach { item -> content.addView(button(item.first) { guide.text = GUIDES[item.second] }) }
        guide = cardText()
        guide.setTextIsSelectable(true)
        guide.text = GUIDES["kit"]
        content.addView(guide)

        content.addView(section("GPS POSITION"))
        content.addView(button("Get GPS coordinates (user action)") { requestLocation() })
        content.addView(button("Open dialer for 911") {
            startActivity(Intent(Intent.ACTION_DIAL, Uri.parse("tel:911")))
        })

        content.addView(section("PRIVATE FIELD NOTES"))
        notes = EditText(this).apply {
            minLines = 4
            maxLines = 8
            gravity = Gravity.TOP
            hint = "Meeting point, supplies, contacts (avoid passwords or secrets)"
            setTextColor(0xff17201b.toInt())
            setHintTextColor(0xff58645c.toInt())
            setBackgroundColor(0xfff8fff9.toInt())
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }
        content.addView(notes, matchWrap())
        content.addView(button("Save notes on this phone") {
            if (notes.text.length > MAX_NOTES_CHARS) toast("Notes are limited to 16,000 characters.")
            else {
                getPreferences(MODE_PRIVATE).edit().putString(NOTES_KEY, notes.text.toString()).apply()
                toast("Saved in Watch-Dawg's private app storage.")
            }
        })
        content.addView(button("Export notes to a file") { exportNotes() })

        content.addView(section("OFFLINE AI ASSISTANT"))
        content.addView(label(
            "Recommended model: Qwen3 0.6B LiteRT-LM, CPU backend. Download the .litertlm file while online, then import it here. " +
                "The model stays in app-private storage. Chat inference does not use a network service.",
            14f, 0xffd4e1d8.toInt()
        ))
        content.addView(button("Import .litertlm model file") { chooseModel() })
        content.addView(button("Load local model") { loadModel() })
        content.addView(button("Remove local model and clear AI") { removeModel() })
        chatLog = cardText().apply {
            setTextIsSelectable(true)
            text = "AI is not loaded. The field guides work without a model."
        }
        content.addView(chatLog)
        question = EditText(this).apply {
            hint = "Ask an offline question"
            setTextColor(0xff17201b.toInt())
            setHintTextColor(0xff58645c.toInt())
            setBackgroundColor(0xfff8fff9.toInt())
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }
        content.addView(question, matchWrap())
        content.addView(button("Ask local AI") { askModel() })
        content.addView(button("Clear conversation from this screen") {
            conversation?.close()
            conversation = null
            chatLog.text = "Conversation cleared. Load the model again for a fresh session."
        })
        content.addView(label(
            "This is a reference aid, not an emergency service, clinician, weather alert, map, or source of current facts. " +
                "For immediate danger, call 911 when service is available and follow local officials. Verify critical advice.",
            13f, 0xffc5d4c8.toInt()
        ))
        return page
    }

    private fun deviceStatus(): String {
        val manager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
        val memory = ActivityManager.MemoryInfo()
        manager.getMemoryInfo(memory)
        val freeStorage = StatFs(filesDir.path).availableBytes / MB
        val abi = if (Build.SUPPORTED_64_BIT_ABIS.isNotEmpty()) "64-bit ABI available" else "32-bit only"
        val model = if (modelFile.exists()) "Model imported (" + modelFile.length() / MB + " MB)." else
            "No model imported; model capacity depends on free memory at load time."
        return "Device check: Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT +
            "); " + memory.totalMem / MB + " MB reported RAM, " + memory.availMem / MB +
            " MB free now; " + freeStorage + " MB app storage free; " + abi + ".\n" + model
    }

    private fun chooseModel() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(intent, REQUEST_MODEL)
    }

    @Deprecated("Legacy result callback kept consistent with this app's current activity style.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        if (requestCode == REQUEST_MODEL) importModel(data.data!!)
        if (requestCode == REQUEST_EXPORT) exportNotesTo(data.data!!)
    }

    private fun importModel(uri: Uri) {
        if (busy) return
        busy = true
        status.text = "Importing model to private app storage…"
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val temp = File(filesDir, MODEL_FILE + ".tmp")
                    contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(temp).use { output ->
                            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                            var bytes = 0L
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                bytes += count
                                if (bytes > MAX_MODEL_BYTES) error("Model file is over the 2 GB import limit.")
                                output.write(buffer, 0, count)
                            }
                            output.fd.sync()
                            if (bytes < MIN_MODEL_BYTES) error("Selected file is too small to be a supported model.")
                        }
                    } ?: error("Android could not open the selected file.")
                    conversation?.close()
                    conversation = null
                    engine?.close()
                    engine = null
                    if (modelFile.exists() && !modelFile.delete()) error("Could not replace the existing model.")
                    if (!temp.renameTo(modelFile)) error("Could not safely finish storing the model.")
                    "Model imported (" + modelFile.length() / MB + " MB). Stored locally and ready to load."
                }.onFailure { File(filesDir, MODEL_FILE + ".tmp").delete() }
            }
            busy = false
            status.text = result.getOrElse { "Import failed: " + (it.message ?: "unknown error") }
            if (result.isSuccess) status.text = deviceStatus()
        }
    }

    private fun loadModel() {
        if (!modelFile.isFile) {
            status.text = "Import a .litertlm model file first."
            return
        }
        if (Build.SUPPORTED_64_BIT_ABIS.isEmpty()) {
            status.text = "This model build needs a 64-bit Android runtime."
            return
        }
        if (busy) return
        busy = true
        chatLog.text = "Loading local model on CPU. First load can take a while…"
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val manager = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                    val memory = ActivityManager.MemoryInfo()
                    manager.getMemoryInfo(memory)
                    if (memory.availMem < MIN_FREE_RAM_BYTES) {
                        error("Android reports less than 900 MB free. Close other apps and retry.")
                    }
                    conversation?.close()
                    conversation = null
                    engine?.close()
                    val localEngine = Engine(
                        EngineConfig(
                            modelPath = modelFile.absolutePath,
                            backend = Backend.CPU(threadCount = 4),
                            maxNumTokens = 2048,
                            cacheDir = cacheDir.absolutePath
                        )
                    )
                    localEngine.initialize()
                    val localConversation = localEngine.createConversation(
                        ConversationConfig(
                            systemInstruction = Contents.of(
                                SYSTEM_INSTRUCTION + "\n\nOffline field guide references:\n" +
                                    GUIDES.values.joinToString("\n\n")
                            )
                        )
                    )
                    engine = localEngine
                    conversation = localConversation
                    "Local AI is ready. Inference runs on the CPU without a network service."
                }
            }
            busy = false
            chatLog.text = result.getOrElse { "Model could not load: " + (it.message ?: "unknown error") }
            status.text = deviceStatus()
        }
    }

    private fun askModel() {
        val chat = conversation
        val prompt = question.text.toString().trim()
        if (chat == null) {
            status.text = "Load the local model before asking a question."
            return
        }
        if (prompt.isBlank() || busy) return
        busy = true
        question.text.clear()
        chatLog.append("\n\nYOU: " + prompt + "\nWATCH-DAWG: ")
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    chat.sendMessageAsync(prompt).collect { part ->
                        if (part.role == Role.MODEL) {
                            val chunk = part.contents.contents
                                .mapNotNull { (it as? com.google.ai.edge.litertlm.Content.Text)?.text }
                                .joinToString("")
                            if (chunk.isNotEmpty()) runOnUiThread { chatLog.append(chunk) }
                        }
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                chatLog.append("\n[Local model error: " + (error.message ?: "unknown error") + "]")
            } finally {
                busy = false
            }
        }
    }

    private fun removeModel() {
        conversation?.close()
        conversation = null
        engine?.close()
        engine = null
        val removed = !modelFile.exists() || modelFile.delete()
        File(filesDir, MODEL_FILE + ".tmp").delete()
        chatLog.text = "Local AI stopped. Conversation is not saved."
        status.text = if (removed) deviceStatus() else "Could not remove local model file."
    }

    private fun requestLocation() {
        val fine = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val coarse = checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!fine && !coarse) {
            requestPermissions(
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                REQUEST_LOCATION
            )
            status.text = "Location permission requested. Tap Get GPS coordinates again after allowing it."
            return
        }
        val manager = getSystemService(LOCATION_SERVICE) as LocationManager
        if (!manager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
            status.text = "Turn on Location in Android settings, then retry. This app does not change settings."
            startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            return
        }
        runCatching { manager.getLastKnownLocation(LocationManager.GPS_PROVIDER) }.getOrNull()?.let {
            displayLocation(it, "Last GPS fix")
        }
        status.text = "Requesting a fresh GPS fix for up to 45 seconds. Go outdoors with a clear sky view."
        val listener = object : LocationListener {
            override fun onLocationChanged(location: Location) {
                displayLocation(location, "GPS fix")
                manager.removeUpdates(this)
                locationListener = null
            }
            @Deprecated("Retained for platform callback compatibility.")
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) = Unit
            override fun onProviderEnabled(provider: String) = Unit
            override fun onProviderDisabled(provider: String) = Unit
        }
        locationListener = listener
        try {
            manager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0L, 0f, listener, Looper.getMainLooper())
            handler.postDelayed({
                if (locationListener === listener) {
                    manager.removeUpdates(listener)
                    locationListener = null
                    status.text = "GPS wait ended without a fresh fix. Try outdoors with Android Location enabled."
                }
            }, LOCATION_TIMEOUT_MS)
        } catch (error: SecurityException) {
            locationListener = null
            status.text = "Android did not grant location access: " + error.message
        }
    }

    private fun displayLocation(location: Location, label: String) {
        guide.text = String.format(
            Locale.US,
            "%s\nLatitude: %.6f\nLongitude: %.6f\nAccuracy: ±%.0f m\nTime: %s",
            label, location.latitude, location.longitude, location.accuracy,
            java.text.DateFormat.getDateTimeInstance().format(Date(location.time))
        )
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("GPS coordinates", guide.text))
        toast("GPS coordinates copied to clipboard.")
    }

    private fun exportNotes() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE, "watch-dawg-survival-notes.txt")
        }
        startActivityForResult(intent, REQUEST_EXPORT)
    }

    private fun exportNotesTo(uri: Uri) {
        runCatching {
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(notes.text.toString()) }
                ?: error("Android could not write to the selected location.")
        }.onSuccess { toast("Notes exported.") }
            .onFailure { status.text = "Notes export failed: " + it.message }
    }

    private fun section(value: String) = label(value, 19f, 0xffbce7a0.toInt(), true).apply {
        setPadding(0, dp(16), 0, dp(5))
    }

    private fun button(title: String, action: () -> Unit) = Button(this).apply {
        text = title
        isAllCaps = false
        setTextColor(0xff102015.toInt())
        setBackgroundColor(0xffbce7a0.toInt())
        layoutParams = LinearLayout.LayoutParams(-1, -2).also { it.bottomMargin = dp(3) }
        setOnClickListener { action() }
    }

    private fun label(value: String, size: Float, color: Int, bold: Boolean = false) =
        TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        }

    private fun cardText() = label("", 15f, 0xffe9f3eb.toInt()).apply {
        setPadding(dp(12), dp(12), dp(12), dp(12))
        setBackgroundColor(0xff1c302b.toInt())
        layoutParams = LinearLayout.LayoutParams(-1, -2).also {
            it.topMargin = dp(5)
            it.bottomMargin = dp(8)
        }
    }

    private fun matchWrap() = LinearLayout.LayoutParams(-1, -2).also { it.topMargin = dp(4) }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    private companion object {
        const val REQUEST_MODEL = 6201
        const val REQUEST_EXPORT = 6202
        const val REQUEST_LOCATION = 6203
        const val MODEL_FILE = "survival-model.litertlm"
        const val NOTES_KEY = "survival_notes_v1"
        const val MAX_NOTES_CHARS = 16_000
        const val MAX_MODEL_BYTES = 2L * 1024 * 1024 * 1024
        const val MIN_MODEL_BYTES = 100L * 1024 * 1024
        const val MIN_FREE_RAM_BYTES = 900L * 1024 * 1024
        const val LOCATION_TIMEOUT_MS = 45_000L
        const val MB = 1024L * 1024L
        const val SYSTEM_INSTRUCTION =
            "You are Watch-Dawg Survival, a cautious offline field reference assistant. You have no live internet, " +
                "weather, emergency dispatch, maps, or current local alerts. Your training can be wrong or out of date. " +
                "State uncertainty plainly, do not invent facts, and advise verifying life-safety instructions with local " +
                "authorities or trusted references. For immediate danger, tell the user to call emergency services when " +
                "available. Do not diagnose or promise rescue."
        val GUIDES = mapOf(
            "kit" to "72-HOUR KIT\n\nStore drinking water, shelf-stable food, needed medicines, first-aid supplies, flashlight, batteries, power bank, charging cable, cash, copies of key documents, sturdy shoes, warm layers, hygiene items, and pet supplies. Keep a written contact and meeting plan. Rotate supplies before expiration. Tailor the kit to household needs.\n\nReady.gov: https://www.ready.gov/kit",
            "water" to "WATER\n\nPrefer sealed commercial water or a source declared safe by public-health officials. Clear water may still contain germs or chemicals. If officials direct you to boil water, bring clear water to a rolling boil for 1 minute (3 minutes above 6,500 feet), then let it cool in a clean covered container. Boiling does not remove fuel, toxic chemicals, or radioactive contamination. If chemical contamination is suspected, use bottled water or another safe source and contact local health officials.\n\nCDC: https://www.cdc.gov/water-emergency/about/",
            "firstaid" to "FIRST AID\n\nFor life-threatening bleeding, call 911 if service is available and apply firm, continuous direct pressure with clean cloth or gauze. Do not remove an embedded object; press around it. For an unresponsive person who is not breathing normally, call emergency services, get an AED if available, and follow dispatcher instructions. Use CPR within your training.\n\nThis short guide is not a first-aid course. Red Cross: https://www.redcross.org/take-a-class/first-aid",
            "weather" to "SEVERE WEATHER\n\nThis app has no live alerts. Keep a battery-powered or hand-crank NOAA Weather Radio if severe weather is a concern. For a tornado warning, move to a basement or small interior room on the lowest floor, away from windows; cover your head and neck. Follow local emergency management instructions.\n\nReady.gov: https://www.ready.gov/tornadoes",
            "power" to "POWER OUTAGE\n\nUse flashlights instead of candles. Keep refrigerator and freezer doors closed. Charge phones from a power bank and reduce screen brightness. Never use a generator, grill, camp stove, or fuel-burning heater indoors or in an attached garage. Place generators outdoors at least 20 feet from doors, windows, and vents; use battery-backed carbon-monoxide alarms.\n\nReady.gov: https://www.ready.gov/power-outages",
            "navigation" to "BASIC NAVIGATION\n\nCarry a paper map of the area and learn to read it before an emergency. A compass requires basic skill. GPS coordinates do not provide a route or map. A satellite fix may be slow or unavailable indoors, underground, under heavy cover, or with a damaged antenna. This app has no offline maps or satellite messaging."
        )
    }
}

