package com.passwordmanager.app

import android.os.Bundle
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.passwordmanager.app.databinding.ActivityMainBinding
import com.passwordmanager.app.databinding.DialogAddEntryBinding
import com.passwordmanager.app.databinding.DialogViewEntryBinding
import com.passwordmanager.app.databinding.DialogLoginBinding
import com.passwordmanager.app.databinding.DialogGetPasswordBinding
import com.passwordmanager.app.databinding.DialogGenerateBinding
import com.passwordmanager.app.db.Entry
import com.passwordmanager.app.db.EntryDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.math.floor

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: EntryDatabase
    private lateinit var adapter: EntriesAdapter
    
    private var isAuthenticated = false
    private var masterPasswordHash: String? = null
    private var masterPassword: String? = null
    private var currentFilter: String = "All"
    private var currentSearch: String = ""
    private var allEntries: List<Entry> = emptyList()
    
    private val importFileLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { importFromUri(it) }
    }
    
    private val exportFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        uri?.let { exportToUri(it) }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        database = EntryDatabase.getInstance(this)
        
        setSupportActionBar(binding.toolbar)
        
        setupRecyclerView()
        setupClickListeners()
        setupSearchAndFilter()
        
        // Check if password is set up
        val prefs = getSharedPreferences("auth", MODE_PRIVATE)
        val existingHash = prefs.getString("master_hash", null)
        
        if (existingHash == null) {
            showSetupDialog()
        } else {
            showLoginDialog()
        }
    }
    
    private fun setupSearchAndFilter() {
        binding.etSearch.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                currentSearch = s?.toString() ?: ""
                if (isAuthenticated) filterEntries()
            }
        })
        
        binding.spinnerCategory.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                currentFilter = parent?.getItemAtPosition(position) as? String ?: "All"
                if (isAuthenticated) filterEntries()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }
    
    private fun showSetupDialog() {
        val dialogBinding = DialogLoginBinding.inflate(layoutInflater)
        dialogBinding.tvTitle.text = "Set Master Password"
        dialogBinding.etPassword.hint = "Create Password (min 8 chars)"
        dialogBinding.etConfirmPassword.visibility = View.VISIBLE
        dialogBinding.tvConfirmLabel.visibility = View.VISIBLE
        dialogBinding.tvConfirmLabel.text = "Minimum 8 characters"
        
        AlertDialog.Builder(this)
            .setView(dialogBinding.root)
            .setPositiveButton("Set Password") { _, _ ->
                val password = dialogBinding.etPassword.text.toString()
                val confirm = dialogBinding.etConfirmPassword.text.toString()
                
                if (password.length < 8) {
                    Toast.makeText(this, "Password must be at least 8 characters", Toast.LENGTH_SHORT).show()
                    showSetupDialog()
                    return@setPositiveButton
                }
                
                if (password != confirm) {
                    Toast.makeText(this, "Passwords don't match", Toast.LENGTH_SHORT).show()
                    showSetupDialog()
                    return@setPositiveButton
                }
                
                // Generate salt and derive hash using PBKDF2
                val salt = CryptoManager.generateSaltBase64()
                val saltBytes = android.util.Base64.decode(salt, android.util.Base64.NO_WRAP)
                masterPasswordHash = CryptoManager.hashPassword(password, saltBytes)
                masterPassword = password  // Store in memory for encryption/decryption
                
                getSharedPreferences("auth", MODE_PRIVATE).edit()
                    .putString("auth_type", "password")
                    .putString("master_hash", masterPasswordHash)
                    .putString("master_salt", salt)
                    .apply()
                
                isAuthenticated = true
                Toast.makeText(this, "Password set!", Toast.LENGTH_SHORT).show()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun showLoginDialog() {
        val dialogBinding = DialogLoginBinding.inflate(layoutInflater)
        dialogBinding.tvTitle.text = "Enter Master Password"
        dialogBinding.etConfirmPassword.visibility = View.GONE
        dialogBinding.tvConfirmLabel.visibility = View.GONE
        
        AlertDialog.Builder(this)
            .setView(dialogBinding.root)
            .setPositiveButton("Unlock") { _, _ ->
                val password = dialogBinding.etPassword.text.toString()
                
                val prefs = getSharedPreferences("auth", MODE_PRIVATE)
                val storedHash = prefs.getString("master_hash", null)
                val storedSalt = prefs.getString("master_salt", null)
                
                // Verify using PBKDF2 (same method as Secure Notes)
                val hash = if (storedSalt != null) {
                    val saltBytes = android.util.Base64.decode(storedSalt, android.util.Base64.NO_WRAP)
                    CryptoManager.hashPassword(password, saltBytes)
                } else {
                    // Legacy: old SHA-256 hash
                    hashString(password)
                }
                
                if (hash == storedHash) {
                    masterPasswordHash = hash
                    masterPassword = password  // Store in memory for encryption/decryption
                    isAuthenticated = true
                    
                    // Migrate legacy salt if missing
                    if (storedSalt == null) {
                        val newSalt = CryptoManager.generateSaltBase64()
                        val saltBytes = android.util.Base64.decode(newSalt, android.util.Base64.NO_WRAP)
                        val newHash = CryptoManager.hashPassword(password, saltBytes)
                        getSharedPreferences("auth", MODE_PRIVATE).edit()
                            .putString("master_hash", newHash)
                            .putString("master_salt", newSalt)
                            .apply()
                        masterPasswordHash = newHash
                    }
                    
                    loadEntries()
                } else {
                    Toast.makeText(this, "Invalid password", Toast.LENGTH_SHORT).show()
                    showLoginDialog()
                }
            }
            .setNegativeButton("Reset Database") { _, _ ->
                showResetDialog()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun showResetDialog() {
        AlertDialog.Builder(this)
            .setTitle("Reset Database")
            .setMessage("This will DELETE ALL passwords! Type 'yes' to confirm:")
            .setView(android.widget.EditText(this).apply {
                hint = "Type yes"
                setPadding(48, 32, 48, 16)
            })
            .setPositiveButton("RESET") { dialog, _ ->
                val editText = (dialog as AlertDialog).findViewById<android.widget.EditText>(android.R.id.custom)
                if (editText?.text.toString().lowercase() == "yes") {
                    resetDatabase()
        } else {
                    Toast.makeText(this, "Cancelled", Toast.LENGTH_SHORT).show()
                    showLoginDialog()
                }
            }
            .setNegativeButton("Cancel") { _, _ ->
                showLoginDialog()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun resetDatabase() {
        lifecycleScope.launch(Dispatchers.IO) {
            database.entryDao().deleteAll()
            getSharedPreferences("auth", MODE_PRIVATE).edit().clear().apply()
            withContext(Dispatchers.Main) {
                Toast.makeText(this@MainActivity, "Database reset", Toast.LENGTH_SHORT).show()
                showSetupDialog()
            }
        }
    }
    
    private fun hashString(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun setupRecyclerView() {
        adapter = EntriesAdapter(
            onViewClick = { entry -> showViewDialog(entry) },
            onCopyClick = { entry -> copyPassword(entry) }
        )
        binding.recyclerEntries.layoutManager = LinearLayoutManager(this)
        binding.recyclerEntries.adapter = adapter
    }
    
    private fun setupClickListeners() {
        binding.fabAdd.setOnClickListener { 
            if (isAuthenticated) showAddDialog() 
        }
    }
    
    private fun loadEntries() {
        lifecycleScope.launch(Dispatchers.IO) {
            allEntries = database.entryDao().getAll()
            withContext(Dispatchers.Main) {
                filterEntries()
                updateCategorySpinner()
            }
        }
    }
    
    private fun filterEntries() {
        var filtered = allEntries
        
        // Apply category filter
        if (currentFilter != "All") {
            filtered = filtered.filter { it.category == currentFilter }
        }
        
        // Apply search filter
        if (currentSearch.isNotEmpty()) {
            val searchLower = currentSearch.lowercase()
            filtered = filtered.filter { 
                it.site.lowercase().contains(searchLower) ||
                it.username.lowercase().contains(searchLower) ||
                it.url.lowercase().contains(searchLower)
            }
        }
        
        adapter.submitList(filtered)
        binding.tvEmptyState.visibility = if (filtered.isEmpty()) View.VISIBLE else View.GONE
        binding.recyclerEntries.visibility = if (filtered.isEmpty()) View.GONE else View.VISIBLE
        
        // Update results count
        val countText = if (filtered.size == allEntries.size) {
            "${filtered.size} entries"
        } else {
            "Showing ${filtered.size} of ${allEntries.size} entries"
        }
        binding.tvResultsCount.text = countText
    }
    
    private fun updateCategorySpinner() {
        lifecycleScope.launch(Dispatchers.IO) {
            val categories = database.entryDao().getAllCategories()
            withContext(Dispatchers.Main) {
                val categoryList = listOf("All") + categories
                val spinnerAdapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_item, categoryList)
                spinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
                binding.spinnerCategory.adapter = spinnerAdapter
                
                val position = categoryList.indexOf(currentFilter)
                if (position >= 0) {
                    binding.spinnerCategory.setSelection(position)
                }
            }
        }
    }
    
    private fun copyPassword(entry: Entry) {
        // Auto-migrate legacy entries
        val currentEntry = migrateEntryIfNeeded(entry) ?: entry
        val password = decryptPassword(currentEntry.passwordEncrypted)
        if (password != null) {
            val clipboard = getSystemService(android.content.ClipboardManager::class.java)
            val clip = android.content.ClipData.newPlainText("Password", password)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "E-D01: Failed to decrypt password", Toast.LENGTH_LONG).show()
        }
    }
    
    private fun copyUsername(entry: Entry) {
        val clipboard = getSystemService(android.content.ClipboardManager::class.java)
        val clip = android.content.ClipData.newPlainText("Username", entry.username)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(this, "Username copied", Toast.LENGTH_SHORT).show()
    }
    
    private fun generatePassword(length: Int = 16): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#\$%^&*"
        val random = SecureRandom()
        return (1..length).map { chars[random.nextInt(chars.length)] }.joinToString("")
    }
    
    private fun showAddDialog() {
        val dialogBinding = DialogAddEntryBinding.inflate(layoutInflater)
        
        // Generate initial password
        dialogBinding.etPassword.setText(generatePassword())
        
        // Setup category spinner
        val categories = listOf("general", "work", "personal", "finance", "social", "other")
        val categoryAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, categories)
        categoryAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        dialogBinding.spinnerCategory.adapter = categoryAdapter
        
        // Generate button
        dialogBinding.btnGenerate.setOnClickListener {
            dialogBinding.etPassword.setText(generatePassword())
        }
        
        AlertDialog.Builder(this)
            .setTitle("Add Entry")
            .setView(dialogBinding.root)
            .setPositiveButton("Add") { _, _ ->
                val site = dialogBinding.etSite.text.toString().trim()
                val username = dialogBinding.etUsername.text.toString().trim()
                val password = dialogBinding.etPassword.text.toString()
                val url = dialogBinding.etUrl.text.toString().trim()
                val notes = dialogBinding.etNotes.text.toString().trim()
                val category = dialogBinding.spinnerCategory.selectedItem.toString()
                
                if (site.isNotEmpty() && username.isNotEmpty() && password.isNotEmpty()) {
                    addEntry(site, username, password, url, notes, category)
        } else {
                    Toast.makeText(this, "Site, username and password required", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun addEntry(site: String, username: String, password: String, url: String, notes: String, category: String) {
        val entry = Entry(
            id = java.util.UUID.randomUUID().toString(),
            site = site,
            username = username,
            passwordEncrypted = encryptPassword(password),
            url = url,
            notes = notes,
            category = category,
            createdAt = System.currentTimeMillis()
        )
        
        lifecycleScope.launch(Dispatchers.IO) {
            database.entryDao().insert(entry)
            withContext(Dispatchers.Main) {
                loadEntries()
                Toast.makeText(this@MainActivity, "Entry added", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showViewDialog(entry: Entry) {
        // Auto-migrate legacy entries
        val currentEntry = migrateEntryIfNeeded(entry) ?: entry
        val dialogBinding = DialogViewEntryBinding.inflate(layoutInflater)
        val decryptedPassword = decryptPassword(currentEntry.passwordEncrypted) ?: ""
        
        dialogBinding.tvSite.text = entry.site
        dialogBinding.tvUsername.text = entry.username
        dialogBinding.tvPassword.text = decryptedPassword
        dialogBinding.tvUrl.text = entry.url.ifEmpty { "-" }
        dialogBinding.tvNotes.text = entry.notes.ifEmpty { "-" }
        dialogBinding.tvCategory.text = entry.category
        
        AlertDialog.Builder(this)
            .setTitle(entry.site)
            .setView(dialogBinding.root)
            .setPositiveButton("Edit") { _, _ ->
                showEditDialog(entry)
            }
            .setNegativeButton("Close", null)
            .setNeutralButton("Copy Password") { _, _ ->
                copyPassword(entry)
            }
            .show()
    }
    
    private fun showEditDialog(entry: Entry) {
        val dialogBinding = DialogAddEntryBinding.inflate(layoutInflater)
        dialogBinding.etSite.setText(entry.site)
        dialogBinding.etUsername.setText(entry.username)
        dialogBinding.etPassword.setText(decryptPassword(entry.passwordEncrypted))
        dialogBinding.etUrl.setText(entry.url)
        dialogBinding.etNotes.setText(entry.notes)
        
        // Setup category spinner
        val categories = listOf("general", "work", "personal", "finance", "social", "other")
        val categoryAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, categories)
        categoryAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        dialogBinding.spinnerCategory.adapter = categoryAdapter
        
        // Set current category
        val categoryPosition = categories.indexOf(entry.category)
        if (categoryPosition >= 0) {
            dialogBinding.spinnerCategory.setSelection(categoryPosition)
        }
        
        // Generate button
        dialogBinding.btnGenerate.setOnClickListener {
            dialogBinding.etPassword.setText(generatePassword())
        }
        
        AlertDialog.Builder(this)
            .setTitle("Edit Entry")
            .setView(dialogBinding.root)
            .setPositiveButton("Save") { _, _ ->
                val updatedEntry = entry.copy(
                    site = dialogBinding.etSite.text.toString().trim(),
                    username = dialogBinding.etUsername.text.toString().trim(),
                    passwordEncrypted = encryptPassword(dialogBinding.etPassword.text.toString()),
                    url = dialogBinding.etUrl.text.toString().trim(),
                    notes = dialogBinding.etNotes.text.toString().trim(),
                    category = dialogBinding.spinnerCategory.selectedItem.toString(),
                    updatedAt = System.currentTimeMillis()
                )
                updateEntry(updatedEntry)
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Delete") { _, _ ->
                showDeleteConfirmation(entry)
            }
            .show()
    }
    
    private fun updateEntry(entry: Entry) {
        lifecycleScope.launch(Dispatchers.IO) {
            database.entryDao().update(entry)
            withContext(Dispatchers.Main) {
                loadEntries()
                Toast.makeText(this@MainActivity, "Entry updated", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showDeleteConfirmation(entry: Entry) {
        AlertDialog.Builder(this)
            .setTitle("Delete Entry")
            .setMessage("Delete ${entry.site}?")
            .setPositiveButton("Delete") { _, _ -> deleteEntry(entry) }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun deleteEntry(entry: Entry) {
        lifecycleScope.launch(Dispatchers.IO) {
            database.entryDao().delete(entry)
            withContext(Dispatchers.Main) {
                loadEntries()
                Toast.makeText(this@MainActivity, "Entry deleted", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showGetPasswordDialog() {
        val dialogBinding = DialogGetPasswordBinding.inflate(layoutInflater)
        
        AlertDialog.Builder(this)
            .setTitle("Get Password")
            .setView(dialogBinding.root)
            .setPositiveButton("Get") { _, _ ->
                val site = dialogBinding.etSite.text.toString().trim()
                if (site.isNotEmpty()) {
                    getPassword(site)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun getPassword(site: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val entry = database.entryDao().getBySite(site)
            withContext(Dispatchers.Main) {
                if (entry != null) {
                    showViewDialog(entry)
        } else {
                    Toast.makeText(this@MainActivity, "Entry not found", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
    
    private fun showGenerateDialog() {
        val dialogBinding = DialogGenerateBinding.inflate(layoutInflater)
        dialogBinding.tvGeneratedPassword.text = generatePassword(16)
        
        dialogBinding.btnGenerate.setOnClickListener {
            val length = dialogBinding.spinnerLength.selectedItem.toString().toIntOrNull() ?: 16
            dialogBinding.tvGeneratedPassword.text = generatePassword(length)
        }
        
        AlertDialog.Builder(this)
            .setTitle("Generate Password")
            .setView(dialogBinding.root)
            .setPositiveButton("Done", null)
            .setNeutralButton("Copy") { _, _ ->
                val clipboard = getSystemService(android.content.ClipboardManager::class.java)
                val clip = android.content.ClipData.newPlainText("Password", dialogBinding.tvGeneratedPassword.text)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show()
            }
            .show()
    }
    
    private fun showDeleteDialog() {
        val editText = android.widget.EditText(this).apply {
            hint = "Enter site name to delete"
            setPadding(48, 32, 48, 16)
        }
        
        AlertDialog.Builder(this)
            .setTitle("Delete Entry")
            .setView(editText)
            .setPositiveButton("Delete") { _, _ ->
                val site = editText.text.toString().trim()
                if (site.isNotEmpty()) {
                    deleteBySite(site)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun deleteBySite(site: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val entry = database.entryDao().getBySite(site)
            withContext(Dispatchers.Main) {
                if (entry != null) {
                    deleteEntry(entry)
        } else {
                    Toast.makeText(this@MainActivity, "Entry not found", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
    
    private fun encryptPassword(password: String): String {
        // Use CryptoManager with the logged-in master password for PBKDF2-derived encryption
        val mp = masterPassword ?: throw Exception("E-E01: Not authenticated — no master password in session")
        return CryptoManager.encrypt(password, mp)
    }
    
    private fun decryptPassword(encrypted: String): String? {
        val mp = masterPassword ?: return null
        // Try new PB: format first (password-derived key)
        val result = CryptoManager.decrypt(encrypted, mp)
        if (result != null) return result
        
        // Fallback: try legacy AndroidKeyStore format for migration
        return decryptLegacyKS(encrypted)
    }
    
    private fun decryptLegacyKS(encrypted: String): String? {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val key = keyStore.getKey("pm_key", null) as? javax.crypto.SecretKey ?: return null
            
            // Try KS: prefix format
            if (encrypted.startsWith("KS:")) {
                val combined = android.util.Base64.decode(encrypted.substring(3), android.util.Base64.NO_WRAP)
                val iv = combined.copyOfRange(0, 12)
                val encryptedBytes = combined.copyOfRange(12, combined.size)
                val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, iv))
                String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
            } else if (encrypted.startsWith("FB:") || encrypted.startsWith("PL:")) {
                // FB or PL formats from previous version — shouldn't be reachable but handle gracefully
                null
            } else {
                // Old format (no prefix) — try AndroidKeyStore
                val combined = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
                if (combined.size < 13) return null
                val iv = combined.copyOfRange(0, 12)
                val encryptedBytes = combined.copyOfRange(12, combined.size)
                val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, iv))
                String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun migrateEntryIfNeeded(entry: Entry): Entry? {
        // Auto-migrate legacy AndroidKeyStore entries to PB: format
        if (entry.passwordEncrypted.startsWith("PB:")) return null // already migrated
        
        val mp = masterPassword ?: return null
        val plaintext = decryptLegacyKS(entry.passwordEncrypted) ?: return null
        
        // Re-encrypt with password-derived key
        val newEncrypted = CryptoManager.encrypt(plaintext, mp)
        val updated = entry.copy(passwordEncrypted = newEncrypted)
        
        // Save migrated entry
        lifecycleScope.launch(Dispatchers.IO) {
            database.entryDao().update(updated)
        }
        return updated
    }
    
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_get_password -> {
                showGetPasswordDialog()
                true
            }
            R.id.action_generate -> {
                showGenerateDialog()
                true
            }
            R.id.action_delete -> {
                showDeleteDialog()
                true
            }
            R.id.action_import -> {
                importFileLauncher.launch("application/json")
                true
            }
            R.id.action_export -> {
                exportFileLauncher.launch("passwords_backup.json")
                true
            }
            R.id.action_lock -> {
                doLock()
                true
            }
            R.id.action_share -> {
                shareApp()
                true
            }
            R.id.action_about -> {
                showAboutDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
    
    private fun doLock() {
        isAuthenticated = false
        masterPasswordHash = null
        masterPassword = null
        getSharedPreferences("auth", MODE_PRIVATE).edit().putBoolean("locked", true).apply()
        adapter.submitList(emptyList())
        showLoginDialog()
        Toast.makeText(this, "Locked", Toast.LENGTH_SHORT).show()
    }
    
    private fun shareApp() {
        val shareIntent = android.content.Intent().apply {
            action = android.content.Intent.ACTION_SEND
            putExtra(android.content.Intent.EXTRA_TEXT, "Password Manager - Secure password storage with AES-256 encryption\n\nGet the latest version:\nhttps://github.com/jnetai-clawbot/Password-Manager/releases")
            type = "text/plain"
        }
        startActivity(android.content.Intent.createChooser(shareIntent, "Share Password Manager"))
    }

    private fun showAboutDialog() {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 32, 48, 16)
        }
        
        // Get actual version from PackageInfo
        val versionName = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown"
        } catch (_: Exception) { "unknown" }
        val versionCode = try {
            packageManager.getPackageInfo(packageName, 0).versionCode
        } catch (_: Exception) { 0 }
        
        val title = android.widget.TextView(this).apply {
            text = "\uD83D\uDD10 Password Manager"
            textSize = 20f
            setTextColor(getColor(com.passwordmanager.app.R.color.primary))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }
        layout.addView(title)
        
        val versionText = android.widget.TextView(this).apply {
            text = "Version $versionName ($versionCode)"
            textSize = 14f
            setTextColor(getColor(com.passwordmanager.app.R.color.text_secondary))
            setPadding(0, 8, 0, 0)
        }
        layout.addView(versionText)
        
        val info = android.widget.TextView(this).apply {
            text = "\nSecure password storage\nAES-256-GCM encryption\nDark theme with Material Design 3\n\nCreated by J~Net 2026"
            textSize = 14f
            setTextColor(getColor(com.passwordmanager.app.R.color.text_primary))
        }
        layout.addView(info)
        
        // Clickable link to jnetai.com
        val jnetLink = android.widget.TextView(this).apply {
            text = "\uD83C\uDF10 jnetai.com"
            textSize = 16f
            setTextColor(getColor(com.passwordmanager.app.R.color.primary))
            setPadding(0, 8, 0, 4)
            setOnClickListener {
                startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("https://jnetai.com")))
            }
        }
        layout.addView(jnetLink)
        
        // Clickable link to GitHub
        val githubLink = android.widget.TextView(this).apply {
            text = "\uD83D\uDCE6 GitHub Repository"
            textSize = 16f
            setTextColor(getColor(com.passwordmanager.app.R.color.primary))
            setPadding(0, 4, 0, 12)
            setOnClickListener {
                startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/jnetai-clawbot/Password-Manager/releases")))
            }
        }
        layout.addView(githubLink)
        
        // Check for Updates button
        val updateBtn = com.google.android.material.button.MaterialButton(this).apply {
            text = "\uD83D\uDD04 Check for Updates"
            setPadding(48, 24, 48, 24)
            cornerRadius = 24
        }
        layout.addView(updateBtn)
        
        // Update status text
        val updateStatus = android.widget.TextView(this).apply {
            text = ""
            textSize = 13f
            setTextColor(getColor(com.passwordmanager.app.R.color.text_secondary))
            setPadding(0, 4, 0, 0)
            visibility = android.view.View.GONE
        }
        layout.addView(updateStatus)
        
        // Download update button (hidden by default)
        val downloadBtn = com.google.android.material.button.MaterialButton(this).apply {
            text = "\u2192 Download Update"
            setPadding(48, 16, 48, 16)
            cornerRadius = 24
            visibility = android.view.View.GONE
        }
        layout.addView(downloadBtn)
        
        val shareBtn = com.google.android.material.button.MaterialButton(this).apply {
            text = "\uD83D\uDCC2 Share App"
            setIconResource(com.passwordmanager.app.R.drawable.ic_share)
            iconGravity = com.google.android.material.button.MaterialButton.ICON_GRAVITY_TEXT_START
            setPadding(48, 24, 48, 24)
            cornerRadius = 24
        }
        layout.addView(shareBtn)
        
        val dialog = AlertDialog.Builder(this)
            .setView(layout)
            .setPositiveButton("OK", null)
            .create()
        
        // Check for updates logic
        updateBtn.setOnClickListener {
            updateBtn.text = "Checking..."
            updateBtn.isEnabled = false
            
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val url = java.net.URL("https://api.github.com/repos/jnetai-clawbot/Password-Manager/releases/latest")
                    val conn = url.openConnection() as java.net.HttpURLConnection
                    conn.requestMethod = "GET"
                    conn.setRequestProperty("Accept", "application/vnd.github.v3+json")
                    conn.connectTimeout = 10000
                    conn.readTimeout = 10000
                    val response = conn.inputStream.bufferedReader().readText()
                    conn.disconnect()
                    
                    val releaseJson = JSONObject(response)
                    val latestTag = releaseJson.optString("tag_name", "unknown")
                    
                    withContext(Dispatchers.Main) {
                        updateStatus.text = "Latest release: $latestTag\nYou have: v$versionName"
                        updateStatus.visibility = android.view.View.VISIBLE
                        updateBtn.text = "\uD83D\uDD04 Check for Updates"
                        updateBtn.isEnabled = true
                        downloadBtn.visibility = android.view.View.VISIBLE
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        updateStatus.text = "Check failed: ${e.message}"
                        updateStatus.visibility = android.view.View.VISIBLE
                        updateBtn.text = "\uD83D\uDD04 Check for Updates"
                        updateBtn.isEnabled = true
                    }
                }
            }
        }
        
        downloadBtn.setOnClickListener {
            startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/jnetai-clawbot/Password-Manager/releases/latest")))
        }
        
        shareBtn.setOnClickListener {
            val shareIntent = android.content.Intent().apply {
                action = android.content.Intent.ACTION_SEND
                putExtra(android.content.Intent.EXTRA_TEXT, "Password Manager - Secure password storage with AES-256 encryption\n\nGet the latest version:\nhttps://github.com/jnetai-clawbot/Password-Manager/releases")
                type = "text/plain"
            }
            startActivity(android.content.Intent.createChooser(shareIntent, "Share Password Manager"))
        }
        
        dialog.show()
    }

    private fun importFromUri(uri: android.net.Uri) {
        val mp = masterPassword
        if (mp == null) {
            Toast.makeText(this, "E-I01: Not authenticated — please unlock first", Toast.LENGTH_LONG).show()
            return
        }
        
        lifecycleScope.launch {
            try {
                // Read file on IO thread
                val (jsonString, json) = withContext(Dispatchers.IO) {
                    val inputStream = contentResolver.openInputStream(uri)
                        ?: throw Exception("E-I02: Cannot open file")
                    val reader = BufferedReader(InputStreamReader(inputStream))
                    val text = reader.readText()
                    reader.close()
                    
                    if (text.isBlank()) {
                        throw Exception("E-I03: File is empty")
                    }
                    
                    try {
                        text to JSONObject(text)
                    } catch (e: Exception) {
                        throw Exception("E-I04: Invalid JSON format — ${e.message}")
                    }
                }
                
                val entriesArray: org.json.JSONArray = if (json.has("entries")) {
                    json.getJSONArray("entries")
                } else {
                    JSONArray().put(json)
                }
                
                if (entriesArray.length() == 0) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "E-I05: No entries found in file", Toast.LENGTH_LONG).show()
                    }
                    return@launch
                }
                
                // Process entries on IO thread
                val result = withContext(Dispatchers.IO) {
                    var imported = 0
                    var skipped = 0
                    var errorDetails = mutableListOf<String>()
                    
                    for (i in 0 until entriesArray.length()) {
                        try {
                            val obj = entriesArray.getJSONObject(i)
                            val site = obj.optString("site", "").trim()
                            val username = obj.optString("username", "").trim()
                            val password = obj.optString("password", "")
                            
                            if (site.isEmpty()) {
                                errorDetails.add("E-I06: Entry ${i+1} missing site field")
                                continue
                            }
                            if (password.isEmpty()) {
                                errorDetails.add("E-I07: $site has empty password")
                                continue
                            }
                            
                            val encryptedPw = CryptoManager.encrypt(password, mp)
                            val verify = CryptoManager.decrypt(encryptedPw, mp)
                            if (verify != password) {
                                errorDetails.add("E-I08: $site encrypt/verify failed")
                                continue
                            }
                            
                            val existing = database.entryDao().getBySite(site)
                            if (existing == null) {
                                val entry = Entry(
                                    id = java.util.UUID.randomUUID().toString(),
                                    site = site,
                                    username = username,
                                    passwordEncrypted = encryptedPw,
                                    url = obj.optString("url", ""),
                                    notes = obj.optString("notes", ""),
                                    category = obj.optString("category", "general"),
                                    createdAt = obj.optLong("createdAt", System.currentTimeMillis())
                                )
                                database.entryDao().insert(entry)
                                imported++
                            } else {
                                skipped++
                            }
                        } catch (e: Exception) {
                            errorDetails.add("E-I10: Entry ${i+1} — ${e.message}")
                        }
                    }
                    
                    Triple(imported, skipped, errorDetails)
                }
                
                val (imported, skipped, errorDetails) = result
                loadEntries()
                
                val msg = buildString {
                    append("Imported: $imported")
                    if (skipped > 0) append("\nSkipped (duplicate): $skipped")
                    if (errorDetails.isNotEmpty()) {
                        append("\nErrors: ${errorDetails.size}")
                        errorDetails.take(3).forEach { append("\n  $it") }
                        if (errorDetails.size > 3) append("\n  ...and ${errorDetails.size - 3} more")
                    }
                }
                Toast.makeText(this@MainActivity, msg, Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                android.util.Log.e("PM_IMPORT", "Import failed", e)
                Toast.makeText(this@MainActivity, "E-I11: Import failed — ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }
    
    private fun exportToUri(uri: android.net.Uri) {
        val mp = masterPassword
        if (mp == null) {
            Toast.makeText(this, "E-X01: Not authenticated — please unlock first", Toast.LENGTH_LONG).show()
            return
        }
        // Read prefs on main thread before launching IO work
        val localSalt = getSharedPreferences("auth", MODE_PRIVATE).getString("master_salt", null)
        
        try {
            lifecycleScope.launch(Dispatchers.IO) {
                val entries = database.entryDao().getAll()
                if (entries.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "E-X01: No entries to export", Toast.LENGTH_LONG).show()
                    }
                    return@launch
                }
                
                val jsonObject = JSONObject()
                val jsonArray = JSONArray()
                var exportErrors = 0
                
                for (entry in entries) {
                    try {
                        // Decrypt using master password (works for both PB: and legacy KS formats)
                        val decryptedPw = decryptPassword(entry.passwordEncrypted)
                        if (decryptedPw == null) {
                            exportErrors++
                            android.util.Log.e("PM_X02", "Failed to decrypt: ${entry.site}")
                            continue
                        }
                        val obj = JSONObject().apply {
                            put("site", entry.site)
                            put("username", entry.username)
                            put("password", decryptedPw)
                            put("url", entry.url)
                            put("notes", entry.notes)
                            put("category", entry.category)
                            put("createdAt", entry.createdAt)
                        }
                        jsonArray.put(obj)
                    } catch (e: Exception) {
                        exportErrors++
                        android.util.Log.e("PM_X03", "Export error: ${entry.site}", e)
                    }
                }
                
                jsonObject.put("version", 2)
                jsonObject.put("app", "password-manager")
                jsonObject.put("exportedAt", System.currentTimeMillis())
                jsonObject.put("entryCount", entries.size)
                jsonObject.put("salt", localSalt ?: "")
                jsonObject.put("entries", jsonArray)
                
                withContext(Dispatchers.Main) {
                    try {
                        contentResolver.openOutputStream(uri)?.use { outputStream ->
                            outputStream.write(jsonObject.toString(2).toByteArray())
                        }
                        val msg = if (exportErrors > 0) {
                            "Exported ${entries.size - exportErrors} of ${entries.size} ($exportErrors errors)"
                        } else {
                            "Exported ${entries.size} entries"
                        }
                        Toast.makeText(this@MainActivity, msg, Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "E-X04: Write failed — ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("PM_EXPORT", "Export failed", e)
            Toast.makeText(this, "E-X05: Export failed — ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

}
