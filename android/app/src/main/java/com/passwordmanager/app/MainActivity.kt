package com.passwordmanager.app

import android.content.Intent
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
import com.passwordmanager.app.databinding.DialogLoginBinding
import com.passwordmanager.app.db.Entry
import com.passwordmanager.app.db.EntryDatabase
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.security.MessageDigest

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: EntryDatabase
    private lateinit var adapter: EntriesAdapter
    private lateinit var googleSignInClient: GoogleSignInClient
    
    private var signedInEmail: String? = null
    private var isAuthenticated = false
    private var masterPasswordHash: String? = null
    
    private val googleSignInLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
        task.addOnCompleteListener { accountTask ->
            if (accountTask.isSuccessful) {
                val account = accountTask.result
                signedInEmail = account.email
                isAuthenticated = true
                getSharedPreferences("auth", MODE_PRIVATE).edit()
                    .putString("auth_type", "google")
                    .putString("user_email", account.email)
                    .apply()
                Toast.makeText(this, "Welcome ${account.email}", Toast.LENGTH_SHORT).show()
                loadEntries()
            } else {
                Toast.makeText(this, "Google Sign-In failed", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
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
        
        setupGoogleSignIn()
        setSupportActionBar(binding.toolbar)
        
        // Check existing auth
        val prefs = getSharedPreferences("auth", MODE_PRIVATE)
        val authType = prefs.getString("auth_type", null)
        
        if (authType == "password") {
            showLoginDialog()
        } else if (authType == "google") {
            val account = GoogleSignIn.getLastSignedInAccount(this)
            if (account != null) {
                signedInEmail = account.email
                isAuthenticated = true
                loadEntries()
            } else {
                showAuthChoiceDialog()
            }
        } else {
            showAuthChoiceDialog()
        }
        
        setupRecyclerView()
        setupClickListeners()
    }
    
    private fun setupGoogleSignIn() {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .build()
        
        googleSignInClient = GoogleSignIn.getClient(this, gso)
    }
    
    private fun showAuthChoiceDialog() {
        val options = arrayOf("Sign in with Google", "Use Master Password")
        
        AlertDialog.Builder(this)
            .setTitle("Password Manager")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> signInWithGoogle()
                    1 -> showSetupOrLoginDialog()
                }
            }
            .setCancelable(false)
            .show()
    }
    
    private fun showSetupOrLoginDialog() {
        val prefs = getSharedPreferences("auth", MODE_PRIVATE)
        val existingHash = prefs.getString("master_hash", null)
        
        if (existingHash == null) {
            showSetupDialog()
        } else {
            showLoginDialog()
        }
    }
    
    private fun showSetupDialog() {
        val dialogBinding = DialogLoginBinding.inflate(layoutInflater)
        dialogBinding.tvTitle.text = "Set Master Password"
        dialogBinding.etPassword.hint = "Create Password (min 6 chars)"
        dialogBinding.etConfirmPassword.visibility = View.VISIBLE
        dialogBinding.tvConfirmLabel.visibility = View.VISIBLE
        
        AlertDialog.Builder(this)
            .setView(dialogBinding.root)
            .setPositiveButton("Set Password") { _, _ ->
                val password = dialogBinding.etPassword.text.toString()
                val confirm = dialogBinding.etConfirmPassword.text.toString()
                
                if (password.length < 6) {
                    Toast.makeText(this, "Password too short", Toast.LENGTH_SHORT).show()
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
            .setNegativeButton("Use Google Instead") { _, _ ->
                signInWithGoogle()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun signInWithGoogle() {
        val signInIntent = googleSignInClient.signInIntent
        googleSignInLauncher.launch(signInIntent)
    }
    
    private fun signOut() {
        googleSignInClient.signOut().addOnCompleteListener(this) {
            signedInEmail = null
            isAuthenticated = false
            getSharedPreferences("auth", MODE_PRIVATE).edit().clear().apply()
            showAuthChoiceDialog()
        }
    }
    
    private fun hashString(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun setupRecyclerView() {
        adapter = EntriesAdapter(
            onCopyClick = { entry -> copyPassword(entry) },
            onViewClick = { entry -> showViewDialog(entry) }
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
            val entries = database.entryDao().getAll()
            withContext(Dispatchers.Main) {
                adapter.submitList(entries)
                binding.tvEmptyState.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
                binding.recyclerEntries.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
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
    
    private fun showAddDialog() {
        val dialogBinding = DialogAddEntryBinding.inflate(layoutInflater)
        
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
                    Toast.makeText(this, "Site, username and password required", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun addEntry(site: String, username: String, password: String, url: String, notes: String) {
        val entry = Entry(
            id = java.util.UUID.randomUUID().toString(),
            site = site,
            username = username,
            passwordEncrypted = encryptPassword(password),
            url = url,
            notes = notes,
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
        
        AlertDialog.Builder(this)
            .setTitle("Edit Entry")
            .setView(dialogBinding.root)
            .setPositiveButton("Save") { _, _ ->
                val updatedEntry = entry.copy(
                    site = dialogBinding.etSite.text.toString().trim(),
                    username = dialogBinding.etUsername.text.toString().trim(),
                    passwordEncrypted = encryptPassword(dialogBinding.etPassword.text.toString()),
                    url = dialogBinding.etUrl.text.toString().trim(),
                    notes = dialogBinding.etNotes.text.toString().trim()
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
    
    private fun encryptPassword(password: String): String {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            if (!keyStore.containsAlias("pm_key")) {
                val kg = javax.crypto.KeyGenerator.getInstance(
                    java.security.KeyStore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                )
                val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                    "pm_key",
                    java.security.KeyStore.KeyProperties.PURPOSE_ENCRYPT or java.security.KeyStore.KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(java.security.KeyStore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(java.security.KeyStore.KeyProperties.ENCRYPTION_PADDING_NONE)
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
            R.id.action_import -> {
                importFileLauncher.launch("application/json")
                true
            }
            R.id.action_export -> {
                exportFileLauncher.launch("passwords_backup.json")
                true
            }
            R.id.action_sign_out -> {
                signOut()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
    
    private fun importFromUri(uri: android.net.Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val jsonString = reader.readText()
            reader.close()
            
            val json = JSONObject(jsonString)
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
