/* Standalone test for add_entry buffer overflow */
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

static char db_path[512] = "./test_passwords.db";
static char current_password[256] = "testmaster";

/* Encryption helpers - COPY from password_manager_gui.c */
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
    fprintf(stderr, "DEBUG [base64_encode]: ENTRY len=%d\n", len);
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
    fprintf(stderr, "DEBUG [base64_encode]: EXIT j=%d\n", j);
    return j;
}

static int base64_decode(const char *in, unsigned char *out) {
    static unsigned char b64map[256] = {0};
    static int init = 0;
    if (!init) {
        const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; b64[i]; i++) b64map[(unsigned char)b64[i]] = i;
        init = 1;
    }
    int len = strlen(in), i, j;
    for (i = 0, j = 0; i < len; i += 4) {
        int a = b64map[(unsigned char)in[i]], b = (i+1 < len && in[i+1] != '=') ? b64map[(unsigned char)in[i+1]] : 0;
        int c = (i+2 < len && in[i+2] != '=') ? b64map[(unsigned char)in[i+2]] : 0;
        int d = (i+3 < len && in[i+3] != '=') ? b64map[(unsigned char)in[i+3]] : 0;
        out[j++] = (a << 2) | (b >> 4);
        if (i+2 < len && in[i+2] != '=') out[j++] = (b << 4) | (c >> 2);
        if (i+3 < len && in[i+3] != '=') out[j++] = (c << 6) | d;
    }
    return j;
}

static int enc_call_count = 0;
static char* encrypt_password(const char *password, const char *master_password) {
    enc_call_count++;
    fprintf(stderr, "DEBUG [encrypt_password]: CALL #%d ENTRY\n", enc_call_count);
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN], ciphertext[1024], tag[16];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(nonce, NONCE_LEN);
    fprintf(stderr, "DEBUG [encrypt_password]: after RAND_bytes\n");
    pbkdf2_derive(master_password, salt, key);
    fprintf(stderr, "DEBUG [encrypt_password]: after pbkdf2_derive\n");
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    
    int len, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)password, strlen(password));
    ciphertext_len += len;
    fprintf(stderr, "DEBUG [encrypt_password]: after EncryptUpdate, len=%d, ciphertext_len=%d\n", len, ciphertext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
    ciphertext_len += len;
    fprintf(stderr, "DEBUG [encrypt_password]: after EncryptFinal, ciphertext_len=%d\n", ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    fprintf(stderr, "DEBUG [encrypt_password]: after cipher free, total stored=%d\n", SALT_LEN + NONCE_LEN + ciphertext_len + 16);
    
    static char result[2048];
    unsigned char combined[2048];
    int combined_len = SALT_LEN + NONCE_LEN + ciphertext_len + 16;
    fprintf(stderr, "DEBUG [encrypt_password]: combined_len=%d (buffer=%zu)\n", combined_len, sizeof(combined));
    memcpy(combined, salt, SALT_LEN);
    memcpy(combined + SALT_LEN, nonce, NONCE_LEN);
    memcpy(combined + SALT_LEN + NONCE_LEN, ciphertext, ciphertext_len);
    memcpy(combined + SALT_LEN + NONCE_LEN + ciphertext_len, tag, 16);
    base64_encode(combined, combined_len, result);
    fprintf(stderr, "DEBUG [encrypt_password]: EXIT, result len=%zu\n", strlen(result));
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
    fprintf(stderr, "DEBUG [add_entry]: ENTRY site='%s' user='%s' pass_len=%zu notes='%s'\n",
            site ? site : "(null)", username ? username : "(null)",
            password ? strlen(password) : 0, notes ? notes : "(null)");
    sqlite3 *db = db_open();
    if (!db) { fprintf(stderr, "DEBUG [add_entry]: db_open failed\n"); return 0; }
    fprintf(stderr, "DEBUG [add_entry]: db opened\n");
    
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
    
    /* Use parameterized query to avoid SQL injection AND buffer overflow */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO entries (id, site, username, password_encrypted, notes) VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "DEBUG [add_entry]: prepare failed\n");
        sqlite3_close(db);
        return 0;
    }
    fprintf(stderr, "DEBUG [add_entry]: prepared, binding...\n");
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    fprintf(stderr, "DEBUG [add_entry]: bound id\n");
    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
    fprintf(stderr, "DEBUG [add_entry]: bound site\n");
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    fprintf(stderr, "DEBUG [add_entry]: bound username\n");
    sqlite3_bind_text(stmt, 4, encrypted, -1, SQLITE_STATIC);
    fprintf(stderr, "DEBUG [add_entry]: bound encrypted password\n");
    sqlite3_bind_text(stmt, 5, notes ? notes : "", -1, SQLITE_STATIC);
    fprintf(stderr, "DEBUG [add_entry]: bound notes, stepping...\n");
    
    int result = (sqlite3_step(stmt) == SQLITE_DONE) ? 1 : 0;
    fprintf(stderr, "DEBUG [add_entry]: step result=%d\n", result);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    fprintf(stderr, "DEBUG [add_entry]: EXIT\n");
    return result;
}

int main(void) {
    unlink(db_path);
    db_init();
    
    /* Set a master password hash so db looks initialized */
    char hash[65];
    sha256_hash("testmaster", hash);
    db_set_setting("master_password_hash", hash);
    
    fprintf(stderr, "\n=== TEST 1: Normal entry ===\n");
    int r1 = add_entry("github.com", "testuser", "secret123", "normal notes");
    fprintf(stderr, "Result: %d\n\n", r1);
    
    fprintf(stderr, "\n=== TEST 2: Entry with long password (stress) ===\n");
    char longpass[256];
    memset(longpass, 'A', 255);
    longpass[255] = '\0';
    int r2 = add_entry("github2.com", "testuser2", longpass, "long password test");
    fprintf(stderr, "Result: %d\n\n", r2);
    
    fprintf(stderr, "\n=== TEST 3: Entry with special chars in password ===\n");
    int r3 = add_entry("github3.com", "testuser3", "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?", "special chars");
    fprintf(stderr, "Result: %d\n\n", r3);
    
    fprintf(stderr, "\n=== TEST 4: Multiple entries (test static buffer reuse) ===\n");
    for (int i = 0; i < 5; i++) {
        char site[64], user[64], pass[64];
        snprintf(site, sizeof(site), "site%d.com", i);
        snprintf(user, sizeof(user), "user%d", i);
        snprintf(pass, sizeof(pass), "pass%d", i);
        fprintf(stderr, "--- Adding entry %d ---\n", i);
        int r = add_entry(site, user, pass, "test notes");
        fprintf(stderr, "Result: %d\n", r);
    }
    
    fprintf(stderr, "\n=== ALL TESTS COMPLETE ===\n");
    return 0;
}
