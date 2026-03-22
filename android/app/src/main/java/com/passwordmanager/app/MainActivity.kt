package com.passwordmanager.app

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
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
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: EntryDatabase
    private lateinit var adapter: EntriesAdapter
    private var masterPasswordHash: String? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        database = EntryDatabase.getInstance(this)
        masterPasswordHash = getSharedPreferences("auth", MODE_PRIVATE).getString("master_hash", null)
        
        if (masterPasswordHash == null) {
            showSetupDialog()
        } else {
            showLoginDialog()
        }
        
        setupRecyclerView()
        setupClickListeners()
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
        
        binding.btnGenerate.setOnClickListener {
            val password = generatePassword(16)
            binding.etPassword.setText(password)
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
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        if (!keyStore.containsAlias("pm_key")) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            )
            val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                "pm_key",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }
        
        val key = keyStore.getKey("pm_key", null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val encrypted = cipher.doFinal(password.toByteArray())
        val iv = cipher.iv
        
        val combined = iv + encrypted
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }
    
    private fun decryptPassword(encrypted: String): String? {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            val key = keyStore.getKey("pm_key", null) as? SecretKey ?: return null
            
            val combined = Base64.decode(encrypted, Base64.NO_WRAP)
            val iv = combined.copyOfRange(0, 12)
            val encryptedBytes = combined.copyOfRange(12, combined.size)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            
            String(cipher.doFinal(encryptedBytes))
        } catch (e: Exception) {
            null
        }
    }
}
