/* Test the GTK flow by simulating what happens when Save is clicked */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

#define KEY_LEN 32
#define SALT_LEN 16
#define NONCE_LEN 12
#define PBKDF2_ITER 10000

static char db_path[512] = "./test_gtk.db";
static char current_password[256] = {0};
static int is_logged_in = 0;

/* COPY all encryption functions from the GUI */
static void sha256_hash(const char *input, char *output) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    for (unsigned int i = 0; i < hash_len; i++)
        sprintf(output + i*2, "%02x", hash[i]);
    output[hash_len*2] = '\0';
}

static int pbkdf2_derive(const char *password, const unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 
                             PBKDF2_ITER, EVP_sha256(), KEY_LEN, key);
}

static int base64_encode(const unsigned char *in, int len, char *out) {
    static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j;
    for (i = 0, j = 0; i < len; i += 3) {
        int a = in[i], b = (i+1 < len) ? in[i+1] : 0, c = (i+2 < len) ? in[i+2] : 0;
        out[j++] = b64chars[(a >> 2) & 0x3F];
        out[j++] = b64chars[((a << 4) | (b >> 4)) & 0x3F];
        out[j++] = (i+1 < len) ? b64chars[((b << 2) | (c >> 6)) & 0x3F] : '=';
        out[j++] = (i+2 < len) ? b64chars[c & 0x3F] : '=';
    }
    out[j] = '\0';
    return j;
}

static int enc_call_count = 0;
static char* encrypt_password(const char *password, const char *master_password) {
    enc_call_count++;
    fprintf(stderr, "DEBUG [encrypt_password]: CALL #%d ENTRY\n", enc_call_count);
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN], ciphertext[1024], tag[16];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(nonce, NONCE_LEN);
    pbkdf2_derive(master_password, salt, key);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    
    int len, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)password, strlen(password));
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    
    static char result[2048];
    unsigned char combined[2048];
    memcpy(combined, salt, SALT_LEN);
    memcpy(combined + SALT_LEN, nonce, NONCE_LEN);
    memcpy(combined + SALT_LEN + NONCE_LEN, ciphertext, ciphertext_len);
    memcpy(combined + SALT_LEN + NONCE_LEN + ciphertext_len, tag, 16);
    base64_encode(combined, SALT_LEN + NONCE_LEN + ciphertext_len + 16, result);
    return result;
}

/* db helpers */
static sqlite3* db_open(void) {
    sqlite3 *db;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) return NULL;
    return db;
}

static void db_init(void) {
    sqlite3 *db = db_open();
    if (!db) return;
    char *err = NULL;
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)", NULL, NULL, &err);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS entries (id TEXT PRIMARY KEY, site TEXT UNIQUE NOT NULL, username TEXT NOT NULL, password_encrypted TEXT NOT NULL, url TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, category TEXT DEFAULT 'general')", NULL, NULL, &err);
    sqlite3_close(db);
}

static int db_set_setting(const char *key, const char *value) {
    sqlite3 *db = db_open();
    if (!db) return 0;
    char sql[1024];
    snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO settings (key, value) VALUES ('%s', '%s')", key, value);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_close(db);
    return 1;
}

static int add_entry(const char *site, const char *username, const char *password, const char *notes) {
    fprintf(stderr, "DEBUG [add_entry]: ENTRY\n");
    sqlite3 *db = db_open();
    if (!db) { fprintf(stderr, "DEBUG [add_entry]: db_open failed\n"); return 0; }
    
    char *encrypted = encrypt_password(password, current_password);
    fprintf(stderr, "DEBUG [add_entry]: after encrypt, encrypted_len=%zu\n", strlen(encrypted));
    
    /* Generate random ID */
    char id[33] = "00000000000000000000000000000000";
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) { 
        if (fread(id, 32, 1, fp) == 1) {
            for (int i = 0; i < 32; i++) sprintf(id + i, "%02x", (unsigned char)id[i]);
            id[32] = '\0';
        }
        fclose(fp); 
    }
    fprintf(stderr, "DEBUG [add_entry]: id='%s'\n", id);
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO entries (id, site, username, password_encrypted, notes) VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, encrypted, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, notes ? notes : "", -1, SQLITE_STATIC);
    
    int result = (sqlite3_step(stmt) == SQLITE_DONE) ? 1 : 0;
    fprintf(stderr, "DEBUG [add_entry]: step result=%d\n", result);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

/* Simulate the full on_add_save_clicked flow */
int main(void) {
    unlink(db_path);
    db_init();
    
    /* Set master password (like setup does) */
    strncpy(current_password, "testmasterpassword", sizeof(current_password) - 1);
    current_password[sizeof(current_password) - 1] = '\0';
    is_logged_in = 1;
    
    char hash[65];
    sha256_hash("testmasterpassword", hash);
    db_set_setting("master_password_hash", hash);
    
    fprintf(stderr, "\n=== Simulating GTK Save click flow ===\n");
    
    /* Simulate the entry text values */
    const char *site = "github.com";
    const char *user = "testuser";
    const char *pass = "secretpassword";
    const char *notes = "";
    
    fprintf(stderr, "DEBUG [simulated click]: site='%s' user='%s' pass_len=%zu notes='%s'\n",
            site, user, strlen(pass), notes);
    fprintf(stderr, "DEBUG [simulated click]: is_logged_in=%d current_password_len=%zu\n",
            is_logged_in, strlen(current_password));
    
    if (!strlen(site) || !strlen(user) || !strlen(pass)) {
        fprintf(stderr, "ERROR: validation failed\n");
        return 1;
    }
    
    fprintf(stderr, "DEBUG [simulated click]: calling add_entry...\n");
    int result = add_entry(site, user, pass, notes);
    fprintf(stderr, "DEBUG [simulated click]: add_entry returned %d\n", result);
    
    /* Simulate freeing entries array */
    char **entries = malloc(sizeof(char*) * 4);
    /* In real GTK code, these would be GtkWidget* but we just use char* for simulation */
    entries[0] = (char*)site; entries[1] = (char*)user; entries[2] = (char*)pass; entries[3] = (char*)notes;
    fprintf(stderr, "DEBUG [simulated click]: entries freed (simulated)\n");
    
    fprintf(stderr, "DEBUG [simulated click]: SUCCESS path - would show_msg now\n");
    
    /* Now test multiple adds (like user might do) */
    for (int i = 0; i < 3; i++) {
        fprintf(stderr, "\n=== Simulating GTK Save click #%d ===\n", i+2);
        char site2[64], user2[64], pass2[64];
        snprintf(site2, sizeof(site2), "site%d.com", i);
        snprintf(user2, sizeof(user2), "user%d", i);
        snprintf(pass2, sizeof(pass2), "pass%d", i);
        int r = add_entry(site2, user2, pass2, "test notes");
        fprintf(stderr, "Result: %d\n", r);
    }
    
    fprintf(stderr, "\n=== ALL TESTS COMPLETE ===\n");
    return 0;
}
