package com.passwordmanager.app

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password-derived encryption using PBKDF2 + AES-256-GCM.
 * Works like Secure Notes: same password on any device can decrypt data
 * because the key is derived from the password + salt (not hardware-bound).
 * 
 * Format: "PB:<base64(salt12><iv12><ciphertext)>"
 * Salt is per-entry (unique per encrypted value) for maximum security.
 * The master salt (stored in prefs) is used for key derivation verification.
 */
object CryptoManager {
    private const val AES_KEY_SIZE = 256
    private const val IV_SIZE = 12
    private const val SALT_SIZE = 16
    private const val ITERATIONS = 10000
    private const val TAG_BITS = 128

    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_SIZE)
        SecureRandom().nextBytes(salt)
        return salt
    }

    fun generateSaltBase64(): String {
        return Base64.encodeToString(generateSalt(), Base64.NO_WRAP)
    }

    /** Derive an AES-256 key from password + salt using PBKDF2 */
    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, AES_KEY_SIZE)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    /** Hash password for authentication (not for encryption) */
    fun hashPassword(password: String, salt: ByteArray): String {
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, AES_KEY_SIZE)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hash = factory.generateSecret(spec).encoded
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /** 
     * Encrypt plaintext using password-derived key.
     * Each encryption uses a unique random salt + IV.
     * Format: "PB:<base64(salt + iv + ciphertext)>"
     */
    fun encrypt(plaintext: String, password: String): String {
        val salt = ByteArray(SALT_SIZE)
        SecureRandom().nextBytes(salt)
        val key = deriveKey(password, salt)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)
        val gcmSpec = GCMParameterSpec(TAG_BITS, iv)
        
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        
        // Combine: [salt(16)][iv(12)][ciphertext]
        val combined = ByteArray(salt.size + iv.size + encrypted.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(encrypted, 0, combined, salt.size + iv.size, encrypted.size)
        
        return "PB:" + Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Decrypt a PB:-prefixed string using the password.
     * The salt is embedded in the ciphertext, so same password = same decryption
     * on any device.
     */
    fun decrypt(encrypted: String, password: String): String? {
        return try {
            if (!encrypted.startsWith("PB:")) return null
            
            val combined = Base64.decode(encrypted.substring(3), Base64.NO_WRAP)
            if (combined.size < SALT_SIZE + IV_SIZE + 1) return null
            
            val salt = combined.copyOfRange(0, SALT_SIZE)
            val iv = combined.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE)
            val ciphertext = combined.copyOfRange(SALT_SIZE + IV_SIZE, combined.size)
            
            val key = deriveKey(password, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(TAG_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
            
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Migrate an old AndroidKeyStore-encrypted entry to new PB: format.
     * Requires the old KS decryption to work AND the current password.
     * Returns the new-format encrypted string, or null if migration fails.
     */
    fun migrateFromKeyStore(ksEncrypted: String, password: String, ksDecrypt: (String) -> String?): String? {
        val plaintext = ksDecrypt(ksEncrypted) ?: return null
        return encrypt(plaintext, password)
    }
}
