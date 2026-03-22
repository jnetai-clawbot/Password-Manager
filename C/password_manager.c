/**
 * Password Manager - C Implementation
 * Secure password storage with master password hash verification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sqlite3.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* Constants */
#define MAX_SITE_LEN 256
#define MAX_USER_LEN 256
#define MAX_PASS_LEN 512
#define MAX_NOTES_LEN 1024
#define MAX_URL_LEN 512
#define MAX_CAT_LEN 128
#define DB_PATH "./passwords.db"

/* Encryption parameters */
#define KEY_LEN 32
#define SALT_LEN 16
#define NONCE_LEN 12
#define PBKDF2_ITER 100000

/* Entry structure */
typedef struct {
    char id[33];
    char site[MAX_SITE_LEN];
    char username[MAX_USER_LEN];
    char password_encrypted[MAX_PASS_LEN * 2];  /* Base64 encrypted */
    char url[MAX_URL_LEN];
    char notes[MAX_NOTES_LEN];
    char created_at[64];
    char updated_at[64];
    char category[MAX_CAT_LEN];
} PMEntry;

/* Global state */
static sqlite3 *db = NULL;
static char master_password_hash[65] = {0};

/* ============================================================================
 * HASHING & ENCRYPTION
 * ============================================================================ */

/**
 * Hash password using SHA-256
 * Stores the hash for verification (one-way)
 */
static int hash_password(const char *password, char *output) {
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    if (!ctx) return 0;
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    
    for (int i = 0; i < 32; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
    
    return 1;
}

/**
 * Verify password against stored hash
 */
static int verify_password(const char *password) {
    char hash[65];
    hash_password(password, hash);
    return strcmp(hash, master_password_hash) == 0;
}

/**
 * Derive key from password using PBKDF2
 */
static int derive_key(const char *password, const unsigned char *salt, 
                      unsigned char *output) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                             salt, SALT_LEN,
                             PBKDF2_ITER, EVP_sha256(),
                             KEY_LEN, output);
}

/**
 * Encrypt data using AES-256-GCM
 * Output format: salt(16) + nonce(12) + ciphertext + tag(16)
 */
static int encrypt_aes_256_gcm(const char *plaintext, const char *password,
                               char *output, int *output_len) {
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char key[KEY_LEN];
    unsigned char iv[NONCE_LEN];
    unsigned char ciphertext[1024];
    unsigned char tag[16];
    int ciphertext_len;
    
    /* Generate random salt and nonce */
    if (!RAND_bytes(salt, SALT_LEN) || !RAND_bytes(nonce, NONCE_LEN)) {
        return 0;
    }
    
    /* Derive key */
    if (!derive_key(password, salt, key)) {
        return 0;
    }
    
    /* Create cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    
    /* Initialize encryption */
    memcpy(iv, nonce, NONCE_LEN);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    /* Encrypt */
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, 
                         (const unsigned char *)plaintext, strlen(plaintext)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;
    
    /* Finalize */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;
    
    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    /* Combine: salt + nonce + ciphertext + tag */
    memcpy(output, salt, SALT_LEN);
    memcpy(output + SALT_LEN, nonce, NONCE_LEN);
    memcpy(output + SALT_LEN + NONCE_LEN, ciphertext, ciphertext_len);
    memcpy(output + SALT_LEN + NONCE_LEN + ciphertext_len, tag, 16);
    
    *output_len = SALT_LEN + NONCE_LEN + ciphertext_len + 16;
    
    /* Base64 encode */
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_F_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, output, *output_len);
    BIO_flush(bio);
    
    int encoded_len = BIO_read(bio, output, *output_len * 2);
    output[encoded_len] = '\0';
    *output_len = encoded_len;
    
    return 1;
}

/**
 * Decrypt data using AES-256-GCM
 */
static int decrypt_aes_256_gcm(const char *encrypted_b64, const char *password,
                               char *plaintext, int *plaintext_len) {
    /* Decode base64 */
    unsigned char combined[2048];
    int combined_len;
    
    BIO *bio = BIO_new_mem_buf(encrypted_b64, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_F_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    combined_len = BIO_read(bio, combined, sizeof(combined));
    BIO_free_all(bio);
    
    if (combined_len < SALT_LEN + NONCE_LEN + 16) {
        return 0;
    }
    
    /* Extract components */
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char ciphertext[1024];
    unsigned char tag[16];
    int ciphertext_len = combined_len - SALT_LEN - NONCE_LEN - 16;
    
    memcpy(salt, combined, SALT_LEN);
    memcpy(nonce, combined + SALT_LEN, NONCE_LEN);
    memcpy(ciphertext, combined + SALT_LEN + NONCE_LEN, ciphertext_len);
    memcpy(tag, combined + SALT_LEN + NONCE_LEN + ciphertext_len, 16);
    
    /* Derive key */
    unsigned char key[KEY_LEN];
    if (!derive_key(password, salt, key)) {
        return 0;
    }
    
    /* Create cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    
    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    /* Decrypt */
    int len;
    if (EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *plaintext_len = len;
    
    /* Finalize and verify tag */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *plaintext_len += len;
    plaintext[*plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    
    return 1;
}

/* ============================================================================
 * DATABASE OPERATIONS
 * ============================================================================ */

/**
 * Initialize database
 */
static int db_init(const char *db_path) {
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    /* Create tables */
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS entries ("
        "   id TEXT PRIMARY KEY,"
        "   site TEXT NOT NULL UNIQUE,"
        "   username TEXT NOT NULL,"
        "   password_encrypted TEXT NOT NULL,"
        "   url TEXT DEFAULT '',"
        "   notes TEXT DEFAULT '',"
        "   created_at TEXT,"
        "   updated_at TEXT,"
        "   category TEXT DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS settings ("
        "   key TEXT PRIMARY KEY,"
        "   value TEXT NOT NULL"
        ");";
    
    char *err_msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    /* Load master password hash */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key = 'master_password_hash'", 
                          -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *hash = (const char *)sqlite3_column_text(stmt, 0);
            strncpy(master_password_hash, hash, 64);
        }
        sqlite3_finalize(stmt);
    }
    
    return 1;
}

/**
 * Close database
 */
static void db_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

/**
 * Get a setting
 */
static const char *db_get_setting(const char *key) {
    static char value[1024];
    sqlite3_stmt *stmt;
    
    snprintf(value, sizeof(value), "SELECT value FROM settings WHERE key = '%s'", key);
    
    if (sqlite3_prepare_v2(db, value, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *result = (const char *)sqlite3_column_text(stmt, 0);
            strncpy(value, result, sizeof(value) - 1);
            sqlite3_finalize(stmt);
            return value;
        }
        sqlite3_finalize(stmt);
    }
    return NULL;
}

/**
 * Set a setting
 */
static int db_set_setting(const char *key, const char *value) {
    sqlite3_stmt *stmt;
    
    if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                          -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

/**
 * Check if master password is set up
 */
static int is_setup(void) {
    return master_password_hash[0] != '\0';
}

/**
 * Set up master password
 */
static int setup_password(const char *password) {
    if (is_setup()) {
        return 0;  /* Already set up */
    }
    
    hash_password(password, master_password_hash);
    return db_set_setting("master_password_hash", master_password_hash);
}

/**
 * Generate random ID
 */
static void generate_id(char *output) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char random_bytes[16];
    
    RAND_bytes(random_bytes, 16);
    
    for (int i = 0; i < 16; i++) {
        output[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
    }
    output[16] = '\0';
}

/**
 * Get current timestamp
 */
static void get_timestamp(char *output, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(output, size, "%Y-%m-%dT%H:%M:%S", tm_info);
}

/**
 * Add an entry
 */
static int pm_add_entry(const char *site, const char *username, const char *password,
                       const char *url, const char *notes, const char *category) {
    char id[33];
    char encrypted[MAX_PASS_LEN * 2];
    int encrypted_len;
    char timestamp[64];
    
    generate_id(id);
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (!encrypt_aes_256_gcm(password, master_password_hash, encrypted, &encrypted_len)) {
        fprintf(stderr, "Encryption failed\n");
        return 0;
    }
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, 
        "INSERT INTO entries (id, site, username, password_encrypted, url, notes, created_at, updated_at, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, encrypted, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, url ? url : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, notes ? notes : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, category ? category : "", -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

/**
 * Get an entry
 */
static PMEntry *pm_get_entry(const char *site) {
    static PMEntry entry;
    sqlite3_stmt *stmt;
    
    memset(&entry, 0, sizeof(entry));
    
    if (sqlite3_prepare_v2(db,
        "SELECT id, site, username, password_encrypted, url, notes, created_at, updated_at, category FROM entries WHERE site = ?",
        -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }
    
    sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        strncpy(entry.id, (const char *)sqlite3_column_text(stmt, 0), 32);
        strncpy(entry.site, (const char *)sqlite3_column_text(stmt, 1), MAX_SITE_LEN - 1);
        strncpy(entry.username, (const char *)sqlite3_column_text(stmt, 2), MAX_USER_LEN - 1);
        strncpy(entry.password_encrypted, (const char *)sqlite3_column_text(stmt, 3), MAX_PASS_LEN * 2 - 1);
        strncpy(entry.url, (const char *)sqlite3_column_text(stmt, 4), MAX_URL_LEN - 1);
        strncpy(entry.notes, (const char *)sqlite3_column_text(stmt, 5), MAX_NOTES_LEN - 1);
        strncpy(entry.created_at, (const char *)sqlite3_column_text(stmt, 6), 63);
        strncpy(entry.updated_at, (const char *)sqlite3_column_text(stmt, 7), 63);
        strncpy(entry.category, (const char *)sqlite3_column_text(stmt, 8), MAX_CAT_LEN - 1);
        
        sqlite3_finalize(stmt);
        return &entry;
    }
    
    sqlite3_finalize(stmt);
    return NULL;
}

/**
 * List all entries
 */
static int pm_list_entries(PMEntry **entries) {
    sqlite3_stmt *stmt;
    int count = 0;
    static PMEntry static_entries[1000];  /* Static buffer for simplicity */
    
    *entries = static_entries;
    memset(static_entries, 0, sizeof(static_entries));
    
    if (sqlite3_prepare_v2(db,
        "SELECT id, site, username, url, category, created_at FROM entries ORDER BY site",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        strncpy(static_entries[count].id, (const char *)sqlite3_column_text(stmt, 0), 32);
        strncpy(static_entries[count].site, (const char *)sqlite3_column_text(stmt, 1), MAX_SITE_LEN - 1);
        strncpy(static_entries[count].username, (const char *)sqlite3_column_text(stmt, 2), MAX_USER_LEN - 1);
        strncpy(static_entries[count].url, (const char *)sqlite3_column_text(stmt, 3), MAX_URL_LEN - 1);
        strncpy(static_entries[count].category, (const char *)sqlite3_column_text(stmt, 4), MAX_CAT_LEN - 1);
        strncpy(static_entries[count].created_at, (const char *)sqlite3_column_text(stmt, 5), 63);
        count++;
    }
    
    sqlite3_finalize(stmt);
    return count;
}

/**
 * Delete an entry
 */
static int pm_delete_entry(const char *site) {
    sqlite3_stmt *stmt;
    
    if (sqlite3_prepare_v2(db, "DELETE FROM entries WHERE site = ?", -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

/**
 * Update an entry's password
 */
static int pm_update_password(const char *site, const char *new_password) {
    char encrypted[MAX_PASS_LEN * 2];
    int encrypted_len;
    char timestamp[64];
    
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (!encrypt_aes_256_gcm(new_password, master_password_hash, encrypted, &encrypted_len)) {
        return 0;
    }
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "UPDATE entries SET password_encrypted = ?, updated_at = ? WHERE site = ?",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, encrypted, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

/**
 * Export entries to JSON file
 * Format compatible with Python and Android versions
 */
static int pm_export_json(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Cannot open file for export: %s\n", filename);
        return 0;
    }
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "SELECT site, username, password_encrypted, url, notes, category FROM entries ORDER BY site",
        -1, &stmt, NULL) != SQLITE_OK) {
        fclose(fp);
        return 0;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"version\": 1,\n");
    fprintf(fp, "  \"app\": \"password-manager\",\n");
    fprintf(fp, "  \"entries\": [\n");
    
    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *site = (const char *)sqlite3_column_text(stmt, 0);
        const char *username = (const char *)sqlite3_column_text(stmt, 1);
        const char *encrypted = (const char *)sqlite3_column_text(stmt, 2);
        const char *url = (const char *)sqlite3_column_text(stmt, 3);
        const char *notes = (const char *)sqlite3_column_text(stmt, 4);
        const char *category = (const char *)sqlite3_column_text(stmt, 5);
        
        // Decrypt password
        char password[MAX_PASS_LEN];
        int password_len;
        if (!decrypt_aes_256_gcm(encrypted, master_password_hash, password, &password_len)) {
            strcpy(password, "");
        }
        
        if (!first) fprintf(fp, ",\n");
        first = 0;
        
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"site\": \"%s\",\n", site ? site : "");
        fprintf(fp, "      \"username\": \"%s\",\n", username ? username : "");
        fprintf(fp, "      \"password\": \"%s\",\n", password);
        fprintf(fp, "      \"url\": \"%s\",\n", url ? url : "");
        fprintf(fp, "      \"notes\": \"%s\",\n", notes ? notes : "");
        fprintf(fp, "      \"category\": \"%s\"\n", category ? category : "");
        fprintf(fp, "    }");
    }
    
    fprintf(fp, "\n  ]\n");
    fprintf(fp, "}\n");
    
    sqlite3_finalize(stmt);
    fclose(fp);
    return 1;
}

/**
 * Import entries from JSON file
 * Format compatible with Python and Android versions
 */
static int pm_import_json(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open file for import: %s\n", filename);
        return 0;
    }
    
    // Read file content
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(fsize + 1);
    fread(content, 1, fsize, fp);
    content[fsize] = '\0';
    fclose(fp);
    
    // Simple JSON parser for import
    // Looks for "site", "username", "password", "url", "notes", "category" fields
    int count = 0;
    char site[MAX_SITE_LEN] = {0};
    char username[MAX_USER_LEN] = {0};
    char password[MAX_PASS_LEN] = {0};
    char url[MAX_URL_LEN] = {0};
    char notes[MAX_NOTES_LEN] = {0};
    char category[MAX_CAT_LEN] = {0};
    
    char *p = content;
    char *end = content + fsize;
    
    while (p < end) {
        // Find "site":"
        if (strstr(p, "\"site\":\"")) {
            p = strstr(p, "\"site\":\"") + 8;
            char *q = strchr(p, '"');
            if (q && q < end) {
                strncpy(site, p, q - p);
                site[q - p] = '\0';
            }
        }
        // Find "username":"
        else if (strstr(p, "\"username\":\"")) {
            p = strstr(p, "\"username\":\"") + 12;
            char *q = strchr(p, '"');
            if (q && q < end) {
                strncpy(username, p, q - p);
                username[q - p] = '\0';
            }
        }
        // Find "password":"
        else if (strstr(p, "\"password\":\"")) {
            p = strstr(p, "\"password\":\"") + 12;
            char *q = strchr(p, '"');
            if (q && q < end) {
                strncpy(password, p, q - p);
                password[q - p] = '\0';
            }
        }
        // Find "url":"
        else if (strstr(p, "\"url\":\"")) {
            p = strstr(p, "\"url\":\"") + 7;
            char *q = strchr(p, '"');
            if (q && q < end) {
                strncpy(url, p, q - p);
                url[q - p] = '\0';
            }
        }
        // Find "notes":"
        else if (strstr(p, "\"notes\":\"")) {
            p = strstr(p, "\"notes\":\"") + 9;
            char *q = strchr(p, '"');
            if (q && q < end) {
                strncpy(notes, p, q - p);
                notes[q - p] = '\0';
            }
        }
        // Find "category":"
        else if (strstr(p, "\"category\":\"")) {
            p = strstr(p, "\"category\":\"") + 12;
            char *q = strchr(p, '"');
            if (q && q < end) {
                strncpy(category, p, q - p);
                category[q - p] = '\0';
            }
            
            // End of entry - add it
            if (site[0] && username[0] && password[0]) {
                if (pm_add_entry(site, username, password, 
                                url[0] ? url : NULL,
                                notes[0] ? notes : NULL,
                                category[0] ? category : NULL)) {
                    count++;
                }
                memset(site, 0, sizeof(site));
                memset(username, 0, sizeof(username));
                memset(password, 0, sizeof(password));
                memset(url, 0, sizeof(url));
                memset(notes, 0, sizeof(notes));
                memset(category, 0, sizeof(category));
            }
        }
        p++;
    }
    
    free(content);
    return count;
}

/**
 * Decrypt and return password for an entry
 */
static char *pm_decrypt_password(const char *encrypted) {
    static char password[MAX_PASS_LEN];
    int password_len;
    
    if (decrypt_aes_256_gcm(encrypted, master_password_hash, password, &password_len)) {
        return password;
    }
    return NULL;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════╗\n");
    printf("  ║     Password Manager - C v1.0         ║\n");
    printf("  ╚══════════════════════════════════════╝\n");
    printf("\n");
}

static void print_usage(const char *program) {
    printf("Usage: %s [options]\n", program);
    printf("\nOptions:\n");
    printf("  --init              Initialize with master password\n");
    printf("  --add SITE USER PASS  Add an entry\n");
    printf("  --list              List all entries\n");
    printf("  --get SITE          Get password for site\n");
    printf("  --delete SITE       Delete entry\n");
    printf("  --db PATH           Database path (default: ./passwords.db)\n");
    printf("  --help              Show this help\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *db_path = DB_PATH;
    const char *action = NULL;
    const char *site = NULL;
    const char *username = NULL;
    const char *password = NULL;
    const char *url = NULL;
    const char *notes = NULL;
    const char *category = NULL;
    char input_password[256];
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--init") == 0) {
            action = "init";
        } else if (strcmp(argv[i], "--add") == 0 && i + 3 < argc) {
            action = "add";
            site = argv[++i];
            username = argv[++i];
            password = argv[++i];
        } else if (strcmp(argv[i], "--list") == 0) {
            action = "list";
        } else if (strcmp(argv[i], "--get") == 0 && i + 1 < argc) {
            action = "get";
            site = argv[++i];
        } else if (strcmp(argv[i], "--delete") == 0 && i + 1 < argc) {
            action = "delete";
            site = argv[++i];
        } else if (strcmp(argv[i], "--update") == 0 && i + 2 < argc) {
            action = "update";
            site = argv[++i];
            password = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    print_banner();
    
    if (!action) {
        print_usage(argv[0]);
        return 0;
    }
    
    /* Initialize database */
    if (!db_init(db_path)) {
        fprintf(stderr, "Failed to initialize database\n");
        return 1;
    }
    
    /* Handle init */
    if (strcmp(action, "init") == 0) {
        printf("Enter master password: ");
        scanf("%255s", input_password);
        
        if (setup_password(input_password)) {
            printf("[OK] Master password set up successfully\n");
        } else {
            printf("[ERROR] Master password already set up\n");
        }
        db_close();
        return 0;
    }
    
    /* Get master password */
    printf("Enter master password: ");
    scanf("%255s", input_password);
    
    if (!verify_password(input_password)) {
        printf("[ERROR] Invalid master password\n");
        db_close();
        return 1;
    }
    
    /* Handle actions */
    if (strcmp(action, "add") == 0) {
        if (pm_add_entry(site, username, password, url, notes, category)) {
            printf("[OK] Added entry: %s\n", site);
        } else {
            printf("[ERROR] Failed to add entry\n");
        }
    }
    else if (strcmp(action, "list") == 0) {
        PMEntry *entries = NULL;
        int count = pm_list_entries(&entries);
        
        printf("\nStored entries (%d):\n", count);
        printf("────────────────────────────────────────────────────────\n");
        
        for (int i = 0; i < count; i++) {
            printf("  %s\n", entries[i].site);
            printf("    Username: %s\n", entries[i].username);
            if (entries[i].url[0]) printf("    URL: %s\n", entries[i].url);
            if (entries[i].category[0]) printf("    Category: %s\n", entries[i].category);
            printf("\n");
        }
    }
    else if (strcmp(action, "get") == 0) {
        PMEntry *entry = pm_get_entry(site);
        if (entry) {
            char *decrypted = pm_decrypt_password(entry->password_encrypted);
            
            printf("\nSite: %s\n", entry->site);
            printf("Username: %s\n", entry->username);
            printf("Password: %s\n", decrypted ? decrypted : "[decryption failed]");
            if (entry->url[0]) printf("URL: %s\n", entry->url);
            if (entry->notes[0]) printf("Notes: %s\n", entry->notes);
        } else {
            printf("[ERROR] Entry not found: %s\n", site);
        }
    }
    else if (strcmp(action, "delete") == 0) {
        printf("Delete %s? (y/N): ", site);
        char confirm;
        scanf(" %c", &confirm);
        
        if (confirm == 'y' || confirm == 'Y') {
            if (pm_delete_entry(site)) {
                printf("[OK] Deleted entry: %s\n", site);
            } else {
                printf("[ERROR] Failed to delete entry\n");
            }
        } else {
            printf("Cancelled.\n");
        }
    }
    else if (strcmp(action, "update") == 0) {
        if (pm_update_password(site, password)) {
            printf("[OK] Updated password for: %s\n", site);
        } else {
            printf("[ERROR] Failed to update password\n");
        }
    }
    
    db_close();
    return 0;
}
