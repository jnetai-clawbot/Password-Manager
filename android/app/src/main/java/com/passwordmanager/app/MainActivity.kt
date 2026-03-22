package com.passwordmanager.app

import android.os.Bundle
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.passwordmanager.app.databinding.ActivityMainBinding
import com.passwordmanager.app.databinding.DialogAddEntryBinding
import com.passwordmanager.app.databinding.DialogViewEntryBinding
import com.passwordmanager.app.db.Entry
import com.passwordmanager.app.db.EntryDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: EntryDatabase
    private lateinit var adapter: EntriesAdapter
    private var masterPasswordHash: String? = null
    
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
        masterPasswordHash = getSharedPreferences("auth", MODE_PRIVATE).getString("master_hash", null)
        
        setSupportActionBar(binding.toolbar)
        
        if (masterPasswordHash == null) {
            showSetupDialog()
        } else {
            showLoginDialog()
        }
        
        setupRecyclerView()
        setupClickListeners()
    }
    
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_import -> {
                importFileLauncher.launch("application/json")
                true
            }
            R.id.action_export -> {
                exportFileLauncher.launch("passwords_backup.json")
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
    
    private fun setupRecyclerView() {
        adapter = EntriesAdapter(
            onClick = { entry -> showEntryDialog(entry) },
            onCopyClick = { entry -> copyPassword(entry) }
        )
        
        binding.recyclerEntries.layoutManager = LinearLayoutManager(this)
        binding.recyclerEntries.adapter = adapter
    }
    
    private fun setupClickListeners() {
        binding.fabAdd.setOnClickListener {
            showAddDialog()
        }
    }
    
    private fun showSetupDialog() {
        val dialogBinding = com.passwordmanager.app.databinding.DialogSetupBinding.inflate(layoutInflater)
        
        AlertDialog.Builder(this)
            .setTitle("Set Up Master Password")
            .setView(dialogBinding.root)
            .setCancelable(false)
            .setPositiveButton("Set Password") { _, _ ->
                val password = dialogBinding.etPassword.text.toString()
                val confirm = dialogBinding.etConfirm.text.toString()
                
                if (password.length < 4) {
                    Toast.makeText(this, "Password too short", Toast.LENGTH_SHORT).show()
                    showSetupDialog()
                    return@setPositiveButton
                }
                
                if (password != confirm) {
                    Toast.makeText(this, "Passwords don't match", Toast.LENGTH_SHORT).show()
                    showSetupDialog()
                    return@setPositiveButton
                }
                
                masterPasswordHash = hashPassword(password)
                getSharedPreferences("auth", MODE_PRIVATE)
                    .edit()
                    .putString("master_hash", masterPasswordHash)
                    .apply()
                
                Toast.makeText(this, "Master password set", Toast.LENGTH_SHORT).show()
                loadEntries()
            }
            .show()
    }
    
    private fun showLoginDialog() {
        val dialogBinding = com.passwordmanager.app.databinding.DialogLoginBinding.inflate(layoutInflater)
        
        AlertDialog.Builder(this)
            .setTitle("Enter Master Password")
            .setView(dialogBinding.root)
            .setCancelable(false)
            .setPositiveButton("Unlock") { _, _ ->
                val password = dialogBinding.etPassword.text.toString()
                
                if (hashPassword(password) != masterPasswordHash) {
                    Toast.makeText(this, "Invalid password", Toast.LENGTH_SHORT).show()
                    showLoginDialog()
                    return@setPositiveButton
                }
                
                Toast.makeText(this, "Welcome!", Toast.LENGTH_SHORT).show()
                loadEntries()
            }
            .setNegativeButton("Exit") { _, _ ->
                finish()
            }
            .show()
    }
    
    private fun showAddDialog() {
        val dialogBinding = DialogAddEntryBinding.inflate(layoutInflater)
        
        dialogBinding.btnGenerate.setOnClickListener {
            dialogBinding.etPassword.setText(generatePassword(16))
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
                
                if (site.isNotEmpty() && username.isNotEmpty() && password.isNotEmpty()) {
                    addEntry(site, username, password, url, notes)
                } else {
                    Toast.makeText(this, "Site, username, and password required", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showEntryDialog(entry: Entry) {
        val decryptedPassword = decryptPassword(entry.passwordEncrypted)
        val dialogBinding = DialogViewEntryBinding.inflate(layoutInflater)
        
        dialogBinding.tvSite.text = entry.site
        dialogBinding.tvUsername.text = entry.username
        dialogBinding.tvPassword.text = decryptedPassword ?: "••••••••"
        dialogBinding.tvUrl.text = entry.url.ifEmpty { "-" }
        dialogBinding.tvNotes.text = entry.notes.ifEmpty { "-" }
        
        AlertDialog.Builder(this)
            .setTitle(entry.site)
            .setView(dialogBinding.root)
            .setPositiveButton("OK", null)
            .setNeutralButton("Copy Password") { _, _ ->
                copyToClipboard(decryptedPassword ?: "")
            }
            .setNegativeButton("Delete") { _, _ ->
                deleteEntry(entry)
            }
            .show()
    }
    
    private fun addEntry(site: String, username: String, password: String, url: String, notes: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val encrypted = encryptPassword(password)
            val entry = Entry(
                id = java.util.UUID.randomUUID().toString(),
                site = site,
                username = username,
                passwordEncrypted = encrypted,
                url = url,
                notes = notes,
                createdAt = System.currentTimeMillis()
            )
            database.entryDao().insert(entry)
            
            withContext(Dispatchers.Main) {
                loadEntries()
                Toast.makeText(this@MainActivity, "Entry added", Toast.LENGTH_SHORT).show()
            }
        }
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
    
    private fun loadEntries() {
        lifecycleScope.launch(Dispatchers.IO) {
            val entries = database.entryDao().getAll()
            withContext(Dispatchers.Main) {
                adapter.submitList(entries)
                binding.tvEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
                binding.recyclerEntries.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
            }
        }
    }
    
    private fun copyPassword(entry: Entry) {
        val password = decryptPassword(entry.passwordEncrypted) ?: return
        copyToClipboard(password)
    }
    
    private fun copyToClipboard(text: String) {
        android.content.ClipboardManager().let { cm ->
            cm.setPrimaryClip(android.content.ClipData.newPlainText("Password", text))
        }
        Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show()
    }
    
    private fun generatePassword(length: Int): String {
        val charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return (1..length).map { charset.random() }.joinToString("")
    }
    
    private fun hashPassword(password: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(password.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }
    
    private fun encryptPassword(password: String): String {
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        if (!keyStore.containsAlias("pm_key")) {
            val keyGenerator = java.security.KeyGenerator.getInstance(
                java.security.KeyStore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            )
            val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                "pm_key",
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }
        
        val key = keyStore.getKey("pm_key", null) as javax.crypto.SecretKey
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
        
        val encrypted = cipher.doFinal(password.toByteArray())
        val iv = cipher.iv
        
        val combined = iv + encrypted
        return Base64.encodeToString(combined, Base64.NO_WRAP)
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
            null
        }
    }
    
    private fun importFromUri(uri: android.net.Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val jsonString = reader.readText()
            reader.close()
            
            val json = JSONObject(jsonString)
            // Support both new format {"entries": [...]} and old format [...]
            val entriesArray = if (json.has("entries")) {
                json.getJSONArray("entries")
            } else {
                json
            }
            
            var imported = 0
            
            for (i in 0 until entriesArray.length()) {
                val obj = entriesArray.getJSONObject(i)
                val site = obj.getString("site")
                val username = obj.getString("username")
                val password = obj.getString("password")
                
                // Check if site already exists
                val existing = database.entryDao().getAll().find { it.site == site }
                if (existing == null) {
                    val entry = Entry(
                        id = java.util.UUID.randomUUID().toString(),
                        site = site,
                        username = username,
                        passwordEncrypted = encryptPassword(password),
                        url = obj.optString("url", ""),
                        notes = obj.optString("notes", ""),
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
