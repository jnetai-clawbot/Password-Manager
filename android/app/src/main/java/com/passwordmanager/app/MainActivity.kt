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
                
                masterPasswordHash = hashString(password)
                getSharedPreferences("auth", MODE_PRIVATE).edit()
                    .putString("auth_type", "password")
                    .putString("master_hash", masterPasswordHash)
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
                val hash = hashString(password)
                
                val prefs = getSharedPreferences("auth", MODE_PRIVATE)
                val storedHash = prefs.getString("master_hash", null)
                
                if (hash == storedHash) {
                    masterPasswordHash = hash
                    isAuthenticated = true
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
        val password = decryptPassword(entry.passwordEncrypted)
        if (password != null) {
            val clipboard = getSystemService(android.content.ClipboardManager::class.java)
            val clip = android.content.ClipData.newPlainText("Password", password)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show()
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
        val dialogBinding = DialogViewEntryBinding.inflate(layoutInflater)
        val decryptedPassword = decryptPassword(entry.passwordEncrypted) ?: ""
        
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
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            if (!keyStore.containsAlias("pm_key")) {
                val kg = javax.crypto.KeyGenerator.getInstance(
                    android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                )
                val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                    "pm_key",
                    android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                
                kg.init(spec)
                kg.generateKey()
            }
            
            val key = keyStore.getKey("pm_key", null) as javax.crypto.SecretKey
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
            
            val encrypted = cipher.doFinal(password.toByteArray())
            val iv = cipher.iv
            
            val combined = iv + encrypted
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Base64.encodeToString(password.toByteArray(), Base64.NO_WRAP)
        }
    }
    
    private fun decryptPassword(encrypted: String): String? {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            val key = keyStore.getKey("pm_key", null) as? javax.crypto.SecretKey ?: return null
            
            val combined = Base64.decode(encrypted, Base64.NO_WRAP)
            val iv = combined.copyOfRange(0, 12)
            val encryptedBytes = combined.copyOfRange(12, combined.size)
            
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec)
            
            String(cipher.doFinal(encryptedBytes))
        } catch (e: Exception) {
            try {
                String(Base64.decode(encrypted, Base64.NO_WRAP))
            } catch (e2: Exception) {
                null
            }
        }
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
        getSharedPreferences("auth", MODE_PRIVATE).edit().putBoolean("locked", true).apply()
        adapter.submitList(emptyList())
        showLoginDialog()
        Toast.makeText(this, "Locked", Toast.LENGTH_SHORT).show()
    }
    
    private fun showAboutDialog() {
        AlertDialog.Builder(this)
            .setTitle("Password Manager")
            .setMessage("Version 1.0\n\nSecure password storage\nAES-256 encryption\n\nCreated by J~Net 2026\njnetai.com")
            .setPositiveButton("OK", null)
            .show()
    }
    
    private fun importFromUri(uri: android.net.Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val jsonString = reader.readText()
            reader.close()
            
            val json = JSONObject(jsonString)
            val entriesArray: org.json.JSONArray = if (json.has("entries")) {
                json.getJSONArray("entries")
        } else {
            }
            
            var imported = 0
            
            for (i in 0 until entriesArray.length()) {
                val obj = entriesArray.getJSONObject(i)
                val site = obj.getString("site")
                val username = obj.getString("username")
                val password = obj.getString("password")
                
                val existing = database.entryDao().getBySite(site)
                if (existing == null) {
                    val entry = Entry(
                        id = java.util.UUID.randomUUID().toString(),
                        site = site,
                        username = username,
                        passwordEncrypted = encryptPassword(password),
                        url = obj.optString("url", ""),
                        notes = obj.optString("notes", ""),
                        category = obj.optString("category", "general"),
                        createdAt = System.currentTimeMillis()
                    )
                    database.entryDao().insert(entry)
                    imported++
                }
            }
            
            loadEntries()
            Toast.makeText(this, "Imported $imported entries", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Import failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun exportToUri(uri: android.net.Uri) {
        try {
            lifecycleScope.launch(Dispatchers.IO) {
                val entries = database.entryDao().getAll()
                val jsonObject = JSONObject()
                val jsonArray = JSONArray()
                
                for (entry in entries) {
                    val obj = JSONObject().apply {
                        put("site", entry.site)
                        put("username", entry.username)
                        put("password", decryptPassword(entry.passwordEncrypted) ?: "")
                        put("url", entry.url)
                        put("notes", entry.notes)
                        put("category", entry.category)
                    }
                    jsonArray.put(obj)
                }
                
                jsonObject.put("version", 1)
                jsonObject.put("app", "password-manager")
                jsonObject.put("entries", jsonArray)
                
                withContext(Dispatchers.Main) {
                    contentResolver.openOutputStream(uri)?.use { outputStream ->
                        outputStream.write(jsonObject.toString(2).toByteArray())
                    }
                    Toast.makeText(this@MainActivity, "Exported ${entries.size} entries", Toast.LENGTH_SHORT).show()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
