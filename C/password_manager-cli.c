/*
 * Password Manager - C Version  
 * Secure password storage with AES-256-GCM encryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <sqlite3.h>

#define MAX_PASS_LEN 256
#define MAX_SITE_LEN 256
#define MAX_USER_LEN 256
#define MAX_URL_LEN 512
#define MAX_NOTES_LEN 1024
#define MAX_CAT_LEN 128
#define MAX_ENTRY_LEN 4096

#define KEY_LEN 32
#define SALT_LEN 16
#define NONCE_LEN 12
#define HASH_LEN 32
#define PBKDF2_ITER 100000
#define DB_PATH "./passwords.db"

static sqlite3 *db = NULL;
static char master_password_hash[65] = {0};

static size_t b64_encode(const unsigned char *in, size_t in_len, char *out) {
    static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    for (i = 0, j = 0; i < in_len; i += 3) {
        int a = in[i];
        int b = (i + 1 < in_len) ? in[i + 1] : 0;
        int c = (i + 2 < in_len) ? in[i + 2] : 0;
        out[j++] = b64_chars[(a >> 2) & 0x3F];
        out[j++] = b64_chars[((a << 4) | (b >> 4)) & 0x3F];
        out[j++] = (i + 1 < in_len) ? b64_chars[((b << 2) | (c >> 6)) & 0x3F] : '=';
        out[j++] = (i + 2 < in_len) ? b64_chars[c & 0x3F] : '=';
    }
    out[j] = '\0';
    return j;
}

static int b64_decode(const char *in, size_t in_len, unsigned char *out, size_t *out_len) {
    static const int b64_decode[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    size_t i, j;
    int a, b, c, d;
    unsigned char tmp[4096];
    size_t tmp_len = 0;
    for (i = 0; i < in_len; i++) {
        if (in[i] == '=' || isspace((unsigned char)in[i])) continue;
        tmp[tmp_len++] = in[i];
    }
    for (i = 0, j = 0; i < tmp_len; i += 4) {
        a = b64_decode[tmp[i]];
        b = (i + 1 < tmp_len) ? b64_decode[tmp[i + 1]] : 0;
        c = (i + 2 < tmp_len) ? b64_decode[tmp[i + 2]] : 0;
        d = (i + 3 < tmp_len) ? b64_decode[tmp[i + 3]] : 0;
        if (a < 0 || b < 0) { *out_len = 0; return 0; }
        out[j++] = (a << 2) | (b >> 4);
        if (i + 2 < tmp_len && c >= 0) out[j++] = ((b & 0x0F) << 4) | (c >> 2);
        if (i + 3 < tmp_len && d >= 0) out[j++] = ((c & 0x03) << 6) | d;
    }
    *out_len = j;
    return 1;
}

static int db_open(const char *path) {
    if (sqlite3_open(path, &db) != SQLITE_OK) return 0;
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)", NULL, NULL, NULL);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS entries ("
        "id TEXT PRIMARY KEY,"
        "site TEXT UNIQUE NOT NULL,"
        "username TEXT NOT NULL,"
        "password_encrypted TEXT NOT NULL,"
        "url TEXT DEFAULT '',"
        "notes TEXT DEFAULT '',"
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT DEFAULT CURRENT_TIMESTAMP,"
        "category TEXT DEFAULT 'general')", NULL, NULL, NULL);
    return 1;
}

static void db_close(void) { if (db) { sqlite3_close(db); db = NULL; } }

static int db_get_setting(const char *key, char *value, size_t value_size) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key = ?", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *result = (const char *)sqlite3_column_text(stmt, 0);
        if (result && value && value_size > 0) {
            strncpy(value, result, value_size - 1);
            value[value_size - 1] = '\0';
        }
        sqlite3_finalize(stmt);
        return 1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static void db_set_setting(const char *key, const char *value) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static int db_add_entry(const char *site, const char *username, const char *encrypted) {
    sqlite3_stmt *stmt;
    char id[33];
    static const char *hex_chars = "0123456789abcdef";
    unsigned char random_bytes[16];
    RAND_bytes(random_bytes, sizeof(random_bytes));
    for (int i = 0; i < 16; i++) {
        id[i * 2] = hex_chars[random_bytes[i] >> 4];
        id[i * 2 + 1] = hex_chars[random_bytes[i] & 0x0F];
    }
    id[32] = '\0';
    if (sqlite3_prepare_v2(db, "INSERT INTO entries (id, site, username, password_encrypted) VALUES (?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, encrypted, -1, SQLITE_STATIC);
    int result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return result;
}

static int db_update_entry(const char *site, const char *encrypted) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "UPDATE entries SET password_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE site = ?", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, encrypted, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
    int result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return result;
}

static int db_delete_entry(const char *site) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "DELETE FROM entries WHERE site = ?", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
    int result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return result;
}

static int db_get_entry(const char *site, char *encrypted_out, size_t enc_size) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT site, username, password_encrypted, url, category FROM entries WHERE site = ?", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *enc = (const char *)sqlite3_column_text(stmt, 2);
        if (encrypted_out && enc) strncpy(encrypted_out, enc, enc_size - 1);
        sqlite3_finalize(stmt);
        return 1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int db_list_entries(char **json_out) {
    sqlite3_stmt *stmt;
    size_t json_size = 8192;
    char *json = malloc(json_size);
    if (!json) return 0;
    strcpy(json, "{\"entries\":[");
    size_t pos = 12;
    if (sqlite3_prepare_v2(db, "SELECT site, username, password_encrypted, url, category FROM entries ORDER BY site", -1, &stmt, NULL) != SQLITE_OK) { free(json); return 0; }
    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *site = (const char *)sqlite3_column_text(stmt, 0);
        const char *user = (const char *)sqlite3_column_text(stmt, 1);
        const char *enc = (const char *)sqlite3_column_text(stmt, 2);
        const char *url = (const char *)sqlite3_column_text(stmt, 3);
        const char *cat = (const char *)sqlite3_column_text(stmt, 4);
        char entry[2048];
        int entry_len = snprintf(entry, sizeof(entry),
            "%c{\"site\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"url\":\"%s\",\"category\":\"%s\"}",
            first ? ' ' : ',', site ? site : "", user ? user : "", enc ? enc : "", url ? url : "", cat ? cat : "");
        if (pos + entry_len > json_size - 1) { json_size *= 2; json = realloc(json, json_size); if (!json) return 0; }
        memcpy(json + pos, entry, entry_len);
        pos += entry_len;
        first = 0;
    }
    sqlite3_finalize(stmt);
    strcpy(json + pos, "]}");
    *json_out = json;
    return 1;
}

static int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, PBKDF2_ITER, EVP_sha256(), KEY_LEN, key);
}

static int hash_password(const char *password, char *hash_out) {
    unsigned char hash[HASH_LEN];
    SHA256((unsigned char *)password, strlen(password), hash);
    for (int i = 0; i < HASH_LEN; i++) sprintf(hash_out + i * 2, "%02x", hash[i]);
    hash_out[HASH_LEN * 2] = '\0';
    return 1;
}

static int encrypt_aes_256_gcm(const char *plaintext, const char *password, char *output, int *output_len) {
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN], ciphertext[1024], tag[16];
    int ciphertext_len;
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(nonce, NONCE_LEN);
    if (!derive_key(password, salt, key)) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)plaintext, strlen(plaintext)) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    unsigned char combined[1024];
    int combined_len = SALT_LEN + NONCE_LEN + ciphertext_len + 16;
    memcpy(combined, salt, SALT_LEN);
    memcpy(combined + SALT_LEN, nonce, NONCE_LEN);
    memcpy(combined + SALT_LEN + NONCE_LEN, ciphertext, ciphertext_len);
    memcpy(combined + SALT_LEN + NONCE_LEN + ciphertext_len, tag, 16);
    char b64[2048];
    size_t b64_len = b64_encode(combined, combined_len, b64);
    b64[b64_len] = '\0';
    strncpy(output, b64, *output_len - 1);
    output[*output_len - 1] = '\0';
    *output_len = (int)b64_len;
    return 1;
}

static int decrypt_aes_256_gcm(const char *encrypted_b64, const char *password, char *plaintext, int *plaintext_len) {
    unsigned char combined[2048];
    size_t combined_len;
    if (!b64_decode(encrypted_b64, strlen(encrypted_b64), combined, &combined_len)) return 0;
    if (combined_len < SALT_LEN + NONCE_LEN + 16) return 0;
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], ciphertext[1024], tag[16];
    int ct_len = (int)(combined_len - SALT_LEN - NONCE_LEN - 16);
    memcpy(salt, combined, SALT_LEN);
    memcpy(nonce, combined + SALT_LEN, NONCE_LEN);
    memcpy(ciphertext, combined + SALT_LEN + NONCE_LEN, ct_len);
    memcpy(tag, combined + SALT_LEN + NONCE_LEN + ct_len, 16);
    unsigned char key[KEY_LEN];
    if (!derive_key(password, salt, key)) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int len;
    if (EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, ciphertext, ct_len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    *plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    *plaintext_len += len;
    plaintext[*plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static int pm_init(const char *db_path) { return db_open(db_path ? db_path : DB_PATH); }

static int pm_verify_password(const char *password) {
    char hash[65], stored[65];
    hash_password(password, hash);
    if (!db_get_setting("master_password_hash", stored, sizeof(stored))) return 0;
    return strcmp(hash, stored) == 0;
}

static int pm_setup_password(const char *password) {
    char hash[65];
    hash_password(password, hash);
    db_set_setting("master_password_hash", hash);
    strncpy(master_password_hash, hash, 64);
    master_password_hash[64] = '\0';
    return 1;
}

static int pm_add_entry(const char *site, const char *username, const char *password) {
    char encrypted[MAX_ENTRY_LEN];
    int enc_len = sizeof(encrypted);
    if (!encrypt_aes_256_gcm(password, master_password_hash, encrypted, &enc_len)) return 0;
    return db_add_entry(site, username, encrypted);
}

static int pm_import_entry(const char *site, const char *username, const char *encrypted_password) {
    return db_add_entry(site, username, encrypted_password);
}

static int pm_get_entry(const char *site, char *password_out, int *pass_len) {
    char encrypted[MAX_ENTRY_LEN];
    if (!db_get_entry(site, encrypted, sizeof(encrypted))) return 0;
    return decrypt_aes_256_gcm(encrypted, master_password_hash, password_out, pass_len);
}

static int pm_list_entries(char **json_out) { return db_list_entries(json_out); }

static int pm_delete_entry(const char *site) { return db_delete_entry(site); }

static int pm_update_password(const char *site, const char *password) {
    char encrypted[MAX_ENTRY_LEN];
    int enc_len = sizeof(encrypted);
    if (!encrypt_aes_256_gcm(password, master_password_hash, encrypted, &enc_len)) return 0;
    return db_update_entry(site, encrypted);
}

static int pm_export_json(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return 0;
    char *json;
    if (!db_list_entries(&json)) { fclose(fp); return 0; }
    fprintf(fp, "%s\n", json);
    free(json);
    fclose(fp);
    return 1;
}

static int pm_import_json(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *content = malloc(fsize + 1);
    size_t read = fread(content, 1, fsize, fp);
    content[read] = '\0';
    fclose(fp);
    int count = 0;
    char *p = content;
    while ((p = strchr(p, '{')) != NULL) {
        char *entry_end = strchr(p, '}');
        if (!entry_end) break;
        *entry_end = '\0';
        char site[256] = {0}, user[256] = {0}, pass[256] = {0};
        char *f;
        if ((f = strstr(p, "\"site\":\"")) != NULL) {
            char *s = f + 8, *e = strchr(s, '"');
            if (e && e - s < sizeof(site)) memcpy(site, s, e - s);
        }
        if ((f = strstr(p, "\"username\":\"")) != NULL) {
            char *s = f + 12, *e = strchr(s, '"');
            if (e && e - s < sizeof(user)) memcpy(user, s, e - s);
        }
        if ((f = strstr(p, "\"password\":\"")) != NULL) {
            char *s = f + 12, *e = strchr(s, '"');
            if (e && e - s < sizeof(pass)) memcpy(pass, s, e - s);
        }
        if (site[0] && user[0] && pass[0]) { pm_import_entry(site, user, pass); count++; }
        p = entry_end + 1;
    }
    free(content);
    return count;
}

static void generate_password(char *output, int len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    unsigned char random[64];
    RAND_bytes(random, len > 32 ? 32 : len);
    for (int i = 0; i < len; i++) output[i] = chars[random[i] % (sizeof(chars) - 1)];
    output[len] = '\0';
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("  --init              Initialize database with master password\n");
    printf("  --add SITE USER PASS  Add new entry\n");
    printf("  --get SITE          Get password for entry\n");
    printf("  --list              List all entries (JSON)\n");
    printf("  --delete SITE       Delete entry\n");
    printf("  --update SITE PASS  Update password for entry\n");
    printf("  --export FILE       Export entries to JSON\n");
    printf("  --import FILE       Import entries from JSON\n");
    printf("  --generate [LEN]    Generate random password\n");
    printf("  --db PATH           Database path (default: ./passwords.db)\n");
    printf("  --help              Show this help\n");
}

int main(int argc, char *argv[]) {
    const char *action = NULL, *site = NULL, *username = NULL, *password = NULL;
    const char *filename = NULL, *db_path = NULL;
    char input_password[MAX_PASS_LEN];
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--init") == 0) action = "init";
        else if (strcmp(argv[i], "--add") == 0 && i + 3 < argc) { action = "add"; site = argv[++i]; username = argv[++i]; password = argv[++i]; }
        else if (strcmp(argv[i], "--get") == 0 && i + 1 < argc) { action = "get"; site = argv[++i]; }
        else if (strcmp(argv[i], "--list") == 0) action = "list";
        else if (strcmp(argv[i], "--delete") == 0 && i + 1 < argc) { action = "delete"; site = argv[++i]; }
        else if (strcmp(argv[i], "--update") == 0 && i + 2 < argc) { action = "update"; site = argv[++i]; password = argv[++i]; }
        else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) { action = "export"; filename = argv[++i]; }
        else if (strcmp(argv[i], "--import") == 0 && i + 1 < argc) { action = "import"; filename = argv[++i]; }
        else if (strcmp(argv[i], "--generate") == 0) action = "generate";
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) db_path = argv[++i];
        else if (strcmp(argv[i], "--help") == 0) { print_usage(argv[0]); return 0; }
    }
    
    if (!action) { print_usage(argv[0]); return 1; }
    
    if (strcmp(action, "generate") == 0) {
        char gen_pass[64];
        int len = 16;
        if (argc > 2 && strcmp(argv[argc-1], "--generate") != 0) {
            len = atoi(argv[argc-1]);
            if (len < 4) len = 4;
            if (len > 64) len = 64;
        }
        generate_password(gen_pass, len);
        printf("%s\n", gen_pass);
        return 0;
    }
    
    if (!pm_init(db_path)) { fprintf(stderr, "Failed to initialize database\n"); return 1; }
    
    if (strcmp(action, "init") == 0) {
        printf("Enter master password: ");
        if (!fgets(input_password, sizeof(input_password), stdin)) { printf("[ERROR] Failed to read password\n"); db_close(); return 1; }
        input_password[strcspn(input_password, "\n")] = '\0';
        if (strlen(input_password) < 8) { printf("[ERROR] Password must be at least 8 characters\n"); db_close(); return 1; }
        if (pm_setup_password(input_password)) printf("[OK] Master password set up successfully\n");
        else printf("[ERROR] Failed to set up password\n");
        db_close();
        return 0;
    }
    
    printf("Enter master password: ");
    if (!fgets(input_password, sizeof(input_password), stdin)) { printf("[ERROR] Failed to read password\n"); db_close(); return 1; }
    input_password[strcspn(input_password, "\n")] = '\0';
    
    char stored_hash[65] = {0};
    db_get_setting("master_password_hash", stored_hash, sizeof(stored_hash));
    if (stored_hash[0] == '\0') {
        if (strcmp(action, "import") != 0) { printf("[ERROR] No master password set. Run with --init first.\n"); db_close(); return 1; }
    } else {
        if (!pm_verify_password(input_password)) { printf("[ERROR] Invalid master password\n"); db_close(); return 1; }
    }
    hash_password(input_password, master_password_hash);
    
    if (strcmp(action, "import") == 0 && stored_hash[0] == '\0') {
        pm_setup_password(input_password);
    }
    
    if (strcmp(action, "add") == 0) {
        if (pm_add_entry(site, username, password)) printf("[OK] Added entry: %s\n", site);
        else printf("[ERROR] Failed to add entry\n");
    }
    else if (strcmp(action, "get") == 0) {
        char pass[MAX_PASS_LEN];
        int pass_len;
        if (pm_get_entry(site, pass, &pass_len)) {
            printf("\n  Site: %s\n", site);
            char site_out[MAX_SITE_LEN], user_out[MAX_USER_LEN], enc[MAX_ENTRY_LEN];
            char url[MAX_URL_LEN], cat[MAX_CAT_LEN];
            if (db_get_entry(site, enc, sizeof(enc))) {
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(db, "SELECT site, username, url, category FROM entries WHERE site = ?", -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        printf("  Username: %s\n", sqlite3_column_text(stmt, 1));
                        printf("  URL: %s\n", sqlite3_column_text(stmt, 2));
                        printf("  Category: %s\n", sqlite3_column_text(stmt, 3));
                    }
                    sqlite3_finalize(stmt);
                }
            }
            printf("  Password: %s\n\n", pass);
        } else printf("[ERROR] Failed to get entry\n");
    }
    else if (strcmp(action, "list") == 0) {
        char *json;
        if (pm_list_entries(&json)) { printf("%s\n", json); free(json); }
        else printf("[]\n");
    }
    else if (strcmp(action, "delete") == 0) {
        if (pm_delete_entry(site)) printf("[OK] Deleted entry: %s\n", site);
        else printf("[ERROR] Failed to delete entry\n");
    }
    else if (strcmp(action, "update") == 0) {
        if (pm_update_password(site, password)) printf("[OK] Updated password for: %s\n", site);
        else printf("[ERROR] Failed to update password\n");
    }
    else if (strcmp(action, "export") == 0) {
        if (pm_export_json(filename)) printf("[OK] Exported entries to: %s\n", filename);
        else printf("[ERROR] Failed to export entries\n");
    }
    else if (strcmp(action, "import") == 0) {
        int count = pm_import_json(filename);
        if (count >= 0) printf("[OK] Imported %d entries from: %s\n", count, filename);
        else printf("[ERROR] Failed to import entries\n");
    }
    
    db_close();
    return 0;
}
