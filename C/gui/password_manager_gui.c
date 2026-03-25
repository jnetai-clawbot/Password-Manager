/*
 * Password Manager - C GTK3 GUI
 * Pure C implementation matching Python version
 * 
 * Build: cd /home/jay/Documents/Scripts/AI/openclaw/job17/C && make gui
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Constants */
#define KEY_LEN 32
#define SALT_LEN 16
#define NONCE_LEN 12
#define PBKDF2_ITER 10000

/* Global widgets */
static GtkWidget *main_window;
static GtkWidget *content_area;
static char current_password[256] = {0};
static int is_logged_in = 0;
static char db_path[512] = "";

/* Global pointer to password entry in Add Entry screen (for Generate button) */
static GtkWidget *g_add_pass_entry = NULL;

/* Global pointer to current list container (for refresh after remove) */
static GtkWidget *g_list_container = NULL;

/* Initialize db_path from current working directory */
static void init_db_path(void) {
    char *cwd = getcwd(db_path, sizeof(db_path) - 64);
    if (cwd) {
        strncat(db_path, "/passwords.db", 64);
    } else {
        snprintf(db_path, sizeof(db_path), "./passwords.db");
    }
}

/* Encryption helpers */
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

/* SHA256 hash with KNOWN output buffer size - safer version */

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


static char* encrypt_password(const char *password, const char *master_password) {
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
    int combined_len = SALT_LEN + NONCE_LEN + ciphertext_len + 16;
    memcpy(combined, salt, SALT_LEN);
    memcpy(combined + SALT_LEN, nonce, NONCE_LEN);
    memcpy(combined + SALT_LEN + NONCE_LEN, ciphertext, ciphertext_len);
    memcpy(combined + SALT_LEN + NONCE_LEN + ciphertext_len, tag, 16);
    base64_encode(combined, combined_len, result);
    return result;
}

static char* decrypt_password(const char *encrypted_b64, const char *master_password) {
    static char result[1024];
    unsigned char combined[2048];
    int combined_len = base64_decode(encrypted_b64, combined);
    if (combined_len < SALT_LEN + NONCE_LEN + 16) return NULL;
    
    unsigned char *salt = combined, *nonce = combined + SALT_LEN;
    unsigned char *ciphertext = combined + SALT_LEN + NONCE_LEN;
    int ciphertext_len = combined_len - SALT_LEN - NONCE_LEN - 16;
    unsigned char *tag = combined + SALT_LEN + NONCE_LEN + ciphertext_len;
    
    unsigned char key[KEY_LEN];
    pbkdf2_derive(master_password, salt, key);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    
    int len, plaintext_len = 0, ret = EVP_DecryptUpdate(ctx, (unsigned char*)result, &len, ciphertext, ciphertext_len);
    if (ret > 0) {
        plaintext_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)result + plaintext_len, &len);
        if (ret > 0) plaintext_len += len;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (plaintext_len <= 0) return NULL;
    result[plaintext_len] = '\0';
    return result;
}

/* Database functions */
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

static char* db_get_setting(const char *key) {
    static char result[512];
    sqlite3 *db = db_open();
    if (!db) return NULL;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key = ?", -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return NULL; }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    result[0] = '\0';
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *val = (const char*)sqlite3_column_text(stmt, 0);
        if (val) strncpy(result, val, sizeof(result) - 1);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result[0] ? result : NULL;
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

static int db_has_password(void) { return db_get_setting("master_password_hash") != NULL; }

static int verify_master_password(const char *password) {
    char stored[65], computed[65];
    char *stored_ptr = db_get_setting("master_password_hash");
    if (!stored_ptr) return 0;
    strncpy(stored, stored_ptr, sizeof(stored) - 1);
    stored[sizeof(stored) - 1] = '\0';
    sha256_hash(password, computed);
    return strcmp(stored, computed) == 0;
}

static int setup_master_password(const char *password) {
    char hash[65];
    sha256_hash(password, hash);
    return db_set_setting("master_password_hash", hash);
}

/* Add entry with notes and category support - uses parameterized query to prevent buffer overflow */
static int add_entry(const char *site, const char *username, const char *password, const char *notes, const char *category) {
    sqlite3 *db = db_open();
    
    char *encrypted = encrypt_password(password, current_password);
    
    /* Generate random ID - use proper buffer size (32 hex bytes = 64 chars + null = 65) */
    unsigned char raw_id[32];
    FILE *fp = fopen("/dev/urandom", "r");
    char id[65];
    if (fp) { 
        if (fread(raw_id, 32, 1, fp) == 1) {
            for (int i = 0; i < 32; i++) snprintf(id + i*2, 3, "%02x", raw_id[i]);
        }
        fclose(fp); 
    } else {
        strncpy(id, "0000000000000000000000000000000000000000000000000000000000000000", sizeof(id));
    }
    id[64] = '\0';
    
    /* Use parameterized query to avoid SQL injection AND buffer overflow */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO entries (id, site, username, password_encrypted, notes, category) VALUES (?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, encrypted, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, notes ? notes : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, category ? category : "general", -1, SQLITE_STATIC);
    
    int result = (sqlite3_step(stmt) == SQLITE_DONE) ? 1 : 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

static int delete_entry(const char *site) {
    sqlite3 *db = db_open();
    if (!db) return 0;
    char sql[1024];
    snprintf(sql, sizeof(sql), "DELETE FROM entries WHERE site = '%s'", site);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    int rows = sqlite3_changes(db);
    sqlite3_close(db);
    return rows > 0;
}

static char* generate_password(int length) {
    static char result[128];
    const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    int n = strlen(chars);
    for (int i = 0; i < length; i++) {
        int r = rand() % n;
        result[i] = chars[r];
    }
    result[length] = '\0';
    return result;
}

/* UI Helpers */
static void clear_content(void) {
    GList *children = gtk_container_get_children(GTK_CONTAINER(content_area));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
}

static void show_msg(GtkMessageType type, const char *title, const char *msg) {
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(main_window), GTK_DIALOG_DESTROY_WITH_PARENT, type, GTK_BUTTONS_OK, "%s", msg);
    gtk_window_set_title(GTK_WINDOW(dialog), title);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static GtkWidget* make_label(const char *text, float size) {
    GtkWidget *label = gtk_label_new(text);
    PangoAttrList *attrs = pango_attr_list_new();
    pango_attr_list_insert(attrs, pango_attr_size_new(size * PANGO_SCALE));
    gtk_label_set_attributes(GTK_LABEL(label), attrs);
    return label;
}

static GtkWidget* make_btn(const char *label, GCallback cb, gpointer data) {
    GtkWidget *btn = gtk_button_new_with_label(label);
    g_signal_connect(btn, "clicked", cb, data);
    gtk_widget_set_size_request(btn, 140, 35);
    return btn;
}

static GtkWidget* make_entry(gboolean visibility) {
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), visibility);
    return entry;
}

static GtkWidget* make_spinbox(int min, int max, int value) {
    GtkWidget *spin = gtk_spin_button_new_with_range(min, max, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin), value);
    return spin;
}

static void copy_to_clipboard(const char *text) {
    GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(clipboard, text, -1);
    gtk_clipboard_store(clipboard);
}

/* Forward declarations */
static void show_main_menu(void);
static void show_setup_screen(void);
static void show_add_entry(void);
static void show_get_password(void);
static void show_list_entries(void);
static void show_delete_entry(void);
static void show_edit_entry(const char *site);
static void show_generate(void);
static void show_export(void);
static void show_import(void);
static void show_about(void);
static void lock_and_login(void);
static void on_remove_btn_clicked(GtkWidget *btn, gpointer data);
static void on_search_changed(GtkWidget *entry, gpointer data);
static void on_clear_search_clicked(GtkWidget *btn, gpointer data);
static void on_toggle_password_visibility(GtkWidget *btn, gpointer data);
static void on_edit_btn_clicked(GtkWidget *btn, gpointer data);
static void refresh_entries_list(GtkWidget *list_container, const char *filter_text);

/* Screen: Login */
static void on_login_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    const char *password = gtk_entry_get_text(GTK_ENTRY(data));
    if (verify_master_password(password)) {
        strncpy(current_password, password, sizeof(current_password) - 1);
        current_password[sizeof(current_password) - 1] = '\0';
        is_logged_in = 1;
        show_main_menu();
    } else {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Invalid password");
    }
}

static void on_reset_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    (void)data;
    FILE *fp = fopen(db_path, "r");
    if (fp) {
        fclose(fp);
        if (unlink(db_path) == 0) {
            show_msg(GTK_MESSAGE_INFO, "Reset", "Database deleted. Restarting...");
            init_db_path();
            db_init();
            memset(current_password, 0, sizeof(current_password));
            is_logged_in = 0;
            show_setup_screen();
        } else {
            show_msg(GTK_MESSAGE_ERROR, "Error", "Failed to delete database");
        }
    } else {
        show_msg(GTK_MESSAGE_INFO, "No Database", "No database found in current directory.");
    }
}

static void show_login_screen(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Enter Master Password:", 14), FALSE, FALSE, 5);
    
    GtkWidget *entry = make_entry(FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 3);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Password");
    gtk_widget_grab_focus(entry);
    g_signal_connect_swapped(entry, "activate", G_CALLBACK(on_login_clicked), entry);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Unlock", G_CALLBACK(on_login_clicked), entry), FALSE, FALSE, 5);
    
    GtkWidget *reset_btn = gtk_button_new_with_label("Reset / Forgot Password");
    gtk_widget_set_size_request(reset_btn, 180, 35);
    g_signal_connect(reset_btn, "clicked", G_CALLBACK(on_reset_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), reset_btn, FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: Setup */
static void on_setup_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **entries = (GtkWidget**)data;
    if (!entries || !entries[0] || !entries[1]) {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Internal error"); free(entries); return;
    }
    const char *pw1 = gtk_entry_get_text(GTK_ENTRY(entries[0]));
    const char *pw2 = gtk_entry_get_text(GTK_ENTRY(entries[1]));
    
    if (strlen(pw1) < 8) { show_msg(GTK_MESSAGE_ERROR, "Error", "Password must be at least 8 characters"); free(entries); return; }
    if (strcmp(pw1, pw2) != 0) { show_msg(GTK_MESSAGE_ERROR, "Error", "Passwords don't match"); free(entries); return; }
    
    if (setup_master_password(pw1)) {
        strncpy(current_password, pw1, sizeof(current_password) - 1);
        current_password[sizeof(current_password) - 1] = '\0';
        is_logged_in = 1;
        free(entries);
        show_msg(GTK_MESSAGE_INFO, "Success", "Master password set!");
        show_main_menu();
    } else {
        free(entries);
        show_msg(GTK_MESSAGE_ERROR, "Error", "Failed to set password");
    }
}

static void show_setup_screen(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Set Up Master Password:", 14), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("(Minimum 8 characters)", 10), FALSE, FALSE, 0);
    
    GtkWidget *entry1 = make_entry(FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry1), "Password");
    gtk_box_pack_start(GTK_BOX(vbox), entry1, FALSE, FALSE, 3);
    
    GtkWidget *entry2 = make_entry(FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry2), "Confirm Password");
    gtk_box_pack_start(GTK_BOX(vbox), entry2, FALSE, FALSE, 3);
    gtk_widget_grab_focus(entry1);
    
    GtkWidget **entries = malloc(sizeof(GtkWidget*) * 2);
    entries[0] = entry1;
    entries[1] = entry2;
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Set Password", G_CALLBACK(on_setup_clicked), entries), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: Main Menu */
static void show_main_menu(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Password Manager", 20), FALSE, FALSE, 8);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_box_pack_start(GTK_BOX(vbox), grid, TRUE, TRUE, 5);
    
    gtk_grid_attach(GTK_GRID(grid), make_btn("Add Entry", G_CALLBACK(show_add_entry), NULL), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("Get Password", G_CALLBACK(show_get_password), NULL), 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("List All", G_CALLBACK(show_list_entries), NULL), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("Generate Password", G_CALLBACK(show_generate), NULL), 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("Export JSON", G_CALLBACK(show_export), NULL), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("Import JSON", G_CALLBACK(show_import), NULL), 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("Lock (Logout)", G_CALLBACK(lock_and_login), NULL), 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_btn("About", G_CALLBACK(show_about), NULL), 1, 3, 1, 1);
    
    gtk_widget_show_all(content_area);
}

/* Screen: Add Entry - callback for Generate button that fills password field */
static void on_gen_for_add_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **ctx = (GtkWidget**)data;
    GtkWidget *pass_entry = ctx[0];
    GtkWidget *len_spin = ctx[1];
    int len = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(len_spin));
    char *pass = generate_password(len);
    gtk_entry_set_text(GTK_ENTRY(pass_entry), pass);
}

/* Screen: Add Entry - Save callback */
static void on_add_save_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **entries = (GtkWidget**)data;
    if (!entries || !entries[0] || !entries[1] || !entries[2] || !entries[3] || !entries[4]) {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Internal error"); free(entries); return;
    }
    const char *site = gtk_entry_get_text(GTK_ENTRY(entries[0]));
    const char *user = gtk_entry_get_text(GTK_ENTRY(entries[1]));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(entries[2]));
    const char *notes = gtk_entry_get_text(GTK_ENTRY(entries[3]));
    const char *category = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(entries[4]));
    
    if (!strlen(site) || !strlen(user) || !strlen(pass)) {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Site, username, and password required"); free(entries); return;
    }
    
    if (add_entry(site, user, pass, notes, category)) {
        free(entries);
        entries = NULL;
        g_add_pass_entry = NULL;  /* Clear global reference */
        show_msg(GTK_MESSAGE_INFO, "Success", "Entry added!");
        show_main_menu();
    } else {
        free(entries);
        entries = NULL;
        g_add_pass_entry = NULL;
        show_msg(GTK_MESSAGE_ERROR, "Error", "Failed to add (site may exist)");
    }
}

static void show_add_entry(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Add New Entry", 16), FALSE, FALSE, 5);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_box_pack_start(GTK_BOX(vbox), grid, TRUE, TRUE, 5);
    
    GtkWidget *site_entry = make_entry(TRUE);
    GtkWidget *user_entry = make_entry(TRUE);
    GtkWidget *pass_entry = make_entry(TRUE);
    GtkWidget *notes_entry = make_entry(TRUE);
    
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Site:"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), site_entry, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Username:"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), user_entry, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Password:"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), pass_entry, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Notes:"), 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), notes_entry, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Category:"), 0, 4, 1, 1);
    
    /* Category dropdown */
    GtkWidget *category_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(category_combo), "general");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(category_combo), "work");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(category_combo), "personal");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(category_combo), "finance");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(category_combo), "social");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(category_combo), "other");
    gtk_combo_box_set_active(GTK_COMBO_BOX(category_combo), 0);  /* Default to "general" */
    gtk_grid_attach(GTK_GRID(grid), category_combo, 1, 4, 1, 1);
    
    gtk_entry_set_placeholder_text(GTK_ENTRY(site_entry), "github.com");
    gtk_entry_set_placeholder_text(GTK_ENTRY(user_entry), "username");
    gtk_entry_set_placeholder_text(GTK_ENTRY(pass_entry), "password");
    gtk_entry_set_placeholder_text(GTK_ENTRY(notes_entry), "optional notes");
    gtk_widget_grab_focus(site_entry);
    
    /* Store pass_entry globally for Generate button */
    g_add_pass_entry = pass_entry;
    
    /* Generate password button row */
    GtkWidget *gen_frame = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_grid_attach(GTK_GRID(grid), gen_frame, 1, 5, 1, 1);
    gtk_box_pack_start(GTK_BOX(gen_frame), make_label("Generate:", 10), FALSE, FALSE, 0);
    GtkWidget *len_spin = make_spinbox(8, 64, 16);
    gtk_box_pack_start(GTK_BOX(gen_frame), len_spin, FALSE, FALSE, 0);
    
    /* Generate button passes password entry and length spinbox */
    GtkWidget *gen_btn = gtk_button_new_with_label("New");
    gtk_box_pack_start(GTK_BOX(gen_frame), gen_btn, FALSE, FALSE, 0);
    
    GtkWidget **gen_ctx = malloc(sizeof(GtkWidget*) * 2);
    gen_ctx[0] = pass_entry;
    gen_ctx[1] = len_spin;
    g_signal_connect(gen_btn, "clicked", G_CALLBACK(on_gen_for_add_clicked), gen_ctx);
    
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), btn_box, FALSE, FALSE, 5);
    
    GtkWidget **entries = malloc(sizeof(GtkWidget*) * 5);
    entries[0] = site_entry;
    entries[1] = user_entry;
    entries[2] = pass_entry;
    entries[3] = notes_entry;
    entries[4] = category_combo;
    gtk_box_pack_start(GTK_BOX(btn_box), make_btn("Save", G_CALLBACK(on_add_save_clicked), entries), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(btn_box), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: Get Password - shows results inline with copy buttons */
static void on_copy_user_clicked(GtkWidget *btn, gpointer data) {
    const char *text = (const char*)data;
    if (!text && btn) text = (const char*)g_object_get_data(G_OBJECT(btn), "text");
    if (!text) return;
    copy_to_clipboard(text);
    show_msg(GTK_MESSAGE_INFO, "Copied", "Username copied to clipboard");
}

static void on_copy_pass_clicked(GtkWidget *btn, gpointer data) {
    const char *text = (const char*)data;
    if (!text && btn) text = (const char*)g_object_get_data(G_OBJECT(btn), "text");
    if (!text) return;
    char *pass = decrypt_password(text, current_password);
    if (pass) {
        copy_to_clipboard(pass);
        show_msg(GTK_MESSAGE_INFO, "Copied", "Password copied to clipboard");
    } else {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Failed to decrypt password");
    }
}

/* Copy URL callback */
static void on_copy_url_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    const char *url = (const char*)data;
    if (!url) return;
    copy_to_clipboard(url);
    show_msg(GTK_MESSAGE_INFO, "Copied", "URL copied to clipboard");
}

static void on_get_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **ctx = (GtkWidget**)data;
    GtkWidget *entry = ctx[0];
    GtkWidget *result_box = ctx[1];
    const char *site = gtk_entry_get_text(GTK_ENTRY(entry));
    if (!strlen(site)) { show_msg(GTK_MESSAGE_ERROR, "Error", "Enter site name"); return; }
    
    sqlite3 *db = db_open();
    if (!db) { show_msg(GTK_MESSAGE_ERROR, "Error", "Database error"); return; }
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT username, password_encrypted, url, notes FROM entries WHERE site = ?", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        show_msg(GTK_MESSAGE_ERROR, "Error", "Database error"); return;
    }
    
    sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
    
    /* Clear previous results */
    GList *children = gtk_container_get_children(GTK_CONTAINER(result_box));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *username = (const char*)sqlite3_column_text(stmt, 0);
        const char *encrypted = (const char*)sqlite3_column_text(stmt, 1);
        const char *url = (const char*)sqlite3_column_text(stmt, 2);
        const char *notes = (const char*)sqlite3_column_text(stmt, 3);
        char *password = decrypt_password(encrypted, current_password);
        
        GtkWidget *grid = gtk_grid_new();
        gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
        gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
        gtk_container_add(GTK_CONTAINER(result_box), grid);
        
        /* Site row */
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Site:"), 0, 0, 1, 1);
        GtkWidget *site_lbl = gtk_label_new(site);
        gtk_grid_attach(GTK_GRID(grid), site_lbl, 1, 0, 1, 1);
        
        /* Username row */
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Username:"), 0, 1, 1, 1);
        GtkWidget *user_lbl = gtk_label_new(username ? username : "");
        gtk_grid_attach(GTK_GRID(grid), user_lbl, 1, 1, 1, 1);
        GtkWidget *copy_user_btn = gtk_button_new_with_label("Copy");
        gtk_button_set_relief(GTK_BUTTON(copy_user_btn), GTK_RELIEF_NONE);
        g_object_set_data_full(G_OBJECT(copy_user_btn), "text", g_strdup(username ? username : ""), g_free);
        g_signal_connect(copy_user_btn, "clicked", G_CALLBACK(on_copy_user_clicked), NULL);
        gtk_grid_attach(GTK_GRID(grid), copy_user_btn, 2, 1, 1, 1);
        
        /* Password row */
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Password:"), 0, 2, 1, 1);
        GtkWidget *pass_lbl = gtk_label_new(password ? password : "***");
        gtk_grid_attach(GTK_GRID(grid), pass_lbl, 1, 2, 1, 1);
        GtkWidget *copy_pass_btn = gtk_button_new_with_label("Copy");
        gtk_button_set_relief(GTK_BUTTON(copy_pass_btn), GTK_RELIEF_NONE);
        g_object_set_data_full(G_OBJECT(copy_pass_btn), "text", g_strdup(encrypted ? encrypted : ""), g_free);
        g_signal_connect(copy_pass_btn, "clicked", G_CALLBACK(on_copy_pass_clicked), NULL);
        gtk_grid_attach(GTK_GRID(grid), copy_pass_btn, 2, 2, 1, 1);
        
        /* URL row */
        int row = 3;
        if (url && strlen(url)) {
            gtk_grid_attach(GTK_GRID(grid), gtk_label_new("URL:"), 0, row, 1, 1);
            GtkWidget *url_lbl = gtk_label_new(url);
            gtk_grid_attach(GTK_GRID(grid), url_lbl, 1, row, 1, 1);
            row++;
        }
        
        /* Notes row */
        if (notes && strlen(notes)) {
            gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Notes:"), 0, row, 1, 1);
            GtkWidget *notes_lbl = gtk_label_new(notes);
            gtk_grid_attach(GTK_GRID(grid), notes_lbl, 1, row, 1, 1);
        }
        
        gtk_widget_show_all(result_box);
    } else {
        GtkWidget *lbl = gtk_label_new("Entry not found");
        gtk_container_add(GTK_CONTAINER(result_box), lbl);
        gtk_widget_show_all(result_box);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

static void show_get_password(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Get Password", 16), FALSE, FALSE, 5);
    
    GtkWidget *entry = make_entry(TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Site name");
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 5);
    gtk_widget_grab_focus(entry);
    
    GtkWidget *result_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_box_pack_start(GTK_BOX(vbox), result_box, FALSE, FALSE, 5);
    
    GtkWidget **ctx = malloc(sizeof(GtkWidget*) * 2);
    ctx[0] = entry;
    ctx[1] = result_box;
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Get", G_CALLBACK(on_get_clicked), ctx), FALSE, FALSE, 5);
    g_signal_connect_swapped(entry, "activate", G_CALLBACK(on_get_clicked), ctx);
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: List Entries */
static void refresh_entries_list(GtkWidget *list_container, const char *filter_text);

/* Remove entry callback */
static void on_remove_btn_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    char *site = (char*)data;
    if (!site) return;
    
    /* Create confirmation dialog */
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Confirm Delete",
        GTK_WINDOW(main_window),
        GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Delete", GTK_RESPONSE_YES,
        NULL);
    
    char msg[512];
    snprintf(msg, sizeof(msg), "Are you sure you want to delete entry for '%s'?", site);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_add(GTK_CONTAINER(content), gtk_label_new(msg));
    gtk_widget_show_all(dialog);
    
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_YES) {
        if (delete_entry(site)) {
            gtk_widget_destroy(dialog);
            g_free(site);
            show_main_menu();  /* Return to home screen instead of staying on list */
            return;
        }
    }
    gtk_widget_destroy(dialog);
    g_free(site);
}

static void on_search_changed(GtkWidget *entry, gpointer data) {
    GtkWidget *list_container = GTK_WIDGET(data);
    const char *filter_text = gtk_entry_get_text(GTK_ENTRY(entry));
    fprintf(stderr, "DEBUG on_search_changed: filter_text='%s'\n", filter_text);
    refresh_entries_list(list_container, filter_text);
}

static void on_clear_search_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **params = (GtkWidget**)data;
    GtkWidget *search_entry = GTK_WIDGET(params[0]);
    GtkWidget *list_container = GTK_WIDGET(params[1]);
    gtk_entry_set_text(GTK_ENTRY(search_entry), "");
    /* Explicitly refresh the list after clearing */
    refresh_entries_list(list_container, "");
}

static void on_toggle_password_visibility(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget *pass_entry = GTK_WIDGET(data);
    gboolean visible = gtk_entry_get_visibility(GTK_ENTRY(pass_entry));
    gtk_entry_set_visibility(GTK_ENTRY(pass_entry), !visible);
}

/* Edit button wrapper callback - properly handles the g_strdup site string */
static void on_edit_btn_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    char *site = (char*)data;
    if (!site) return;
    show_edit_entry(site);
    g_free(site);  /* Free the g_strdup-ed site string */
}

static void refresh_entries_list(GtkWidget *list_container, const char *filter_text);

static void refresh_list_after_action(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **ctx = (GtkWidget**)data;
    GtkWidget *list_container = ctx[0];
    GtkWidget *search_entry = ctx[1];
    const char *filter = gtk_entry_get_text(GTK_ENTRY(search_entry));
    refresh_entries_list(list_container, filter);
    free(ctx);
}

static void refresh_entries_list(GtkWidget *list_container, const char *filter_text) {
    /* Remove all children from the list container */
    GList *children = gtk_container_get_children(GTK_CONTAINER(list_container));
    for (GList *l = children; l != NULL; l = g_list_next(l)) {
        gtk_widget_destroy(GTK_WIDGET(l->data));
    }
    g_list_free(children);

    if (!is_logged_in) return;

    sqlite3 *db = db_open();
    if (!db) return;

    /* Use parameterized queries to prevent SQL injection and handle search properly */
    sqlite3_stmt *stmt;
    int search_len = (filter_text && strlen(filter_text) > 0) ? strlen(filter_text) : 0;
    
    fprintf(stderr, "DEBUG refresh_entries_list: filter_text='%s', search_len=%d\n", 
            filter_text ? filter_text : "(null)", search_len);
    
    fprintf(stderr, "DEBUG: search filter_text='%s', search_len=%d\n", 
            filter_text ? filter_text : "(null)", search_len);
    
    if (search_len > 0) {
        if (sqlite3_prepare_v2(db,
            "SELECT site, username, password_encrypted, notes, category FROM entries "
            "WHERE site LIKE ? ORDER BY site", -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "DEBUG: prepare failed: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return;
        }
        /* Build pattern with wildcards - use SQLITE_TRANSIENT so SQLite copies the string */
        char pattern[256];
        snprintf(pattern, sizeof(pattern), "%%%s%%", filter_text);
        fprintf(stderr, "DEBUG: LIKE pattern='%s'\n", pattern);
        sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);
    } else {
        fprintf(stderr, "DEBUG: showing ALL entries (no filter)\n");
        if (sqlite3_prepare_v2(db,
            "SELECT site, username, password_encrypted, notes, category FROM entries ORDER BY site",
            -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "DEBUG: prepare failed: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return;
        }
    }

    int row = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        row++;
        const char *site = (const char*)sqlite3_column_text(stmt, 0);
        const char *user = (const char*)sqlite3_column_text(stmt, 1);
        const char *enc  = (const char*)sqlite3_column_text(stmt, 2);
        const char *notes = (const char*)sqlite3_column_text(stmt, 3);
        const char *cat = (const char*)sqlite3_column_text(stmt, 4);

        /* Each entry is a card/frame with vertical layout */
        GtkWidget *card = gtk_frame_new(NULL);
        gtk_widget_set_halign(card, GTK_ALIGN_FILL);
        gtk_widget_set_valign(card, GTK_ALIGN_START);
        gtk_widget_set_hexpand(card, FALSE);
        gtk_widget_set_vexpand(card, FALSE);
        gtk_widget_set_margin_top(card, 6);
        gtk_widget_set_margin_bottom(card, 6);
        gtk_widget_set_margin_start(card, 4);
        gtk_widget_set_margin_end(card, 4);
        gtk_frame_set_shadow_type(GTK_FRAME(card), GTK_SHADOW_ETCHED_IN);
        gtk_box_pack_start(GTK_BOX(list_container), card, FALSE, FALSE, 0);
        fprintf(stderr, "DEBUG: adding card for site=%s\n", site);

        /* Card content - vertical box */
        GtkWidget *card_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
        gtk_widget_set_margin_start(card_box, 10);
        gtk_widget_set_margin_end(card_box, 10);
        gtk_widget_set_margin_top(card_box, 8);
        gtk_widget_set_margin_bottom(card_box, 8);
        gtk_container_add(GTK_CONTAINER(card), card_box);

        /* Site name as header */
        GtkWidget *site_lbl = gtk_label_new(site ? site : "");
        gtk_widget_set_halign(site_lbl, GTK_ALIGN_START);
        PangoAttrList *attrs = pango_attr_list_new();
        pango_attr_list_insert(attrs, pango_attr_size_new(14 * PANGO_SCALE));
        pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        gtk_label_set_attributes(GTK_LABEL(site_lbl), attrs);
        gtk_box_pack_start(GTK_BOX(card_box), site_lbl, FALSE, FALSE, 0);

        /* Username row - NO expand */
        GtkWidget *user_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_box_pack_start(GTK_BOX(card_box), user_box, FALSE, FALSE, 0);

        GtkWidget *user_lbl = gtk_label_new(user ? user : "");
        gtk_widget_set_halign(user_lbl, GTK_ALIGN_START);
        gtk_label_set_selectable(GTK_LABEL(user_lbl), TRUE);
        gtk_box_pack_start(GTK_BOX(user_box), user_lbl, TRUE, TRUE, 0);

        GtkWidget *copy_user_btn = gtk_button_new_with_label("Copy Username");
        gtk_button_set_relief(GTK_BUTTON(copy_user_btn), GTK_RELIEF_NONE);
        gtk_widget_set_valign(copy_user_btn, GTK_ALIGN_CENTER);
        gtk_widget_set_size_request(copy_user_btn, 120, 28);
        g_signal_connect(copy_user_btn, "clicked", G_CALLBACK(on_copy_user_clicked), g_strdup(user ? user : ""));
        gtk_box_pack_start(GTK_BOX(user_box), copy_user_btn, FALSE, FALSE, 0);

        /* Password row - NO expand */
        char *pass = decrypt_password(enc, current_password);
        GtkWidget *pass_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_box_pack_start(GTK_BOX(card_box), pass_box, FALSE, FALSE, 0);

        GtkWidget *pass_lbl = gtk_label_new(pass ? pass : "***");
        gtk_widget_set_halign(pass_lbl, GTK_ALIGN_START);
        gtk_label_set_selectable(GTK_LABEL(pass_lbl), TRUE);
        gtk_box_pack_start(GTK_BOX(pass_box), pass_lbl, TRUE, TRUE, 0);

        GtkWidget *copy_pass_btn = gtk_button_new_with_label("Copy Password");
        gtk_button_set_relief(GTK_BUTTON(copy_pass_btn), GTK_RELIEF_NONE);
        gtk_widget_set_valign(copy_pass_btn, GTK_ALIGN_CENTER);
        gtk_widget_set_size_request(copy_pass_btn, 120, 28);
        g_signal_connect(copy_pass_btn, "clicked", G_CALLBACK(on_copy_pass_clicked), g_strdup(enc ? enc : ""));
        gtk_box_pack_start(GTK_BOX(pass_box), copy_pass_btn, FALSE, FALSE, 0);

        /* Notes row (if present) - NO expand */
        if (notes && strlen(notes) > 0) {
            GtkWidget *notes_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
            gtk_box_pack_start(GTK_BOX(card_box), notes_box, FALSE, FALSE, 0);

            GtkWidget *notes_title_lbl = gtk_label_new("Notes:");
            gtk_widget_set_halign(notes_title_lbl, GTK_ALIGN_START);
            PangoAttrList *nattrs = pango_attr_list_new();
            pango_attr_list_insert(nattrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
            pango_attr_list_insert(nattrs, pango_attr_size_new(9 * PANGO_SCALE));
            gtk_label_set_attributes(GTK_LABEL(notes_title_lbl), nattrs);
            gtk_box_pack_start(GTK_BOX(notes_box), notes_title_lbl, FALSE, FALSE, 0);

            GtkWidget *notes_lbl = gtk_label_new(notes);
            gtk_widget_set_halign(notes_lbl, GTK_ALIGN_START);
            gtk_label_set_selectable(GTK_LABEL(notes_lbl), TRUE);
            gtk_label_set_line_wrap(GTK_LABEL(notes_lbl), TRUE);
            gtk_box_pack_start(GTK_BOX(notes_box), notes_lbl, TRUE, TRUE, 0);
        }

        /* Category row - plaintext, not encrypted, always show */
        GtkWidget *cat_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_box_pack_start(GTK_BOX(card_box), cat_box, FALSE, FALSE, 0);

        GtkWidget *cat_title_lbl = gtk_label_new("Category:");
        gtk_widget_set_halign(cat_title_lbl, GTK_ALIGN_START);
        PangoAttrList *cattrs = pango_attr_list_new();
        pango_attr_list_insert(cattrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        pango_attr_list_insert(cattrs, pango_attr_size_new(9 * PANGO_SCALE));
        gtk_label_set_attributes(GTK_LABEL(cat_title_lbl), cattrs);
        gtk_box_pack_start(GTK_BOX(cat_box), cat_title_lbl, FALSE, FALSE, 0);

        GtkWidget *cat_lbl = gtk_label_new(cat ? cat : "general");
        gtk_widget_set_halign(cat_lbl, GTK_ALIGN_START);
        gtk_label_set_selectable(GTK_LABEL(cat_lbl), TRUE);
        gtk_box_pack_start(GTK_BOX(cat_box), cat_lbl, TRUE, TRUE, 0);

        /* Action buttons row - NO expand */
        GtkWidget *action_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_box_pack_start(GTK_BOX(card_box), action_box, FALSE, FALSE, 4);

        /* Spacer to push buttons to the right */
        GtkWidget *spacer = gtk_label_new("");
        gtk_box_pack_start(GTK_BOX(action_box), spacer, TRUE, TRUE, 0);

        GtkWidget *edit_btn = gtk_button_new_with_label("Edit");
        gtk_button_set_relief(GTK_BUTTON(edit_btn), GTK_RELIEF_NONE);
        gtk_widget_set_valign(edit_btn, GTK_ALIGN_CENTER);
        gtk_widget_set_size_request(edit_btn, 80, 28);
        g_signal_connect(edit_btn, "clicked", G_CALLBACK(on_edit_btn_clicked), g_strdup(site ? site : ""));
        gtk_box_pack_start(GTK_BOX(action_box), edit_btn, FALSE, FALSE, 0);

        GtkWidget *remove_btn = gtk_button_new_with_label("Remove");
        gtk_button_set_relief(GTK_BUTTON(remove_btn), GTK_RELIEF_NONE);
        gtk_widget_set_valign(remove_btn, GTK_ALIGN_CENTER);
        gtk_widget_set_size_request(remove_btn, 80, 28);
        /* Store site name for the callback */
        g_signal_connect(remove_btn, "clicked", G_CALLBACK(on_remove_btn_clicked), g_strdup(site ? site : ""));
        gtk_box_pack_start(GTK_BOX(action_box), remove_btn, FALSE, FALSE, 0);

        fprintf(stderr, "DEBUG: added card for site=%s\n", site);
    }
    fprintf(stderr, "DEBUG: query returned %d rows\n", row);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    fprintf(stderr, "DEBUG: card packed, showing widgets\n");
    fflush(stderr);
    gtk_widget_show_all(list_container);
    fflush(stderr);
}

static void show_list_entries(void) {
    clear_content();
    
    /* Set larger window size for this view */
    gtk_window_set_default_size(GTK_WINDOW(main_window), 900, 700);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);

    /* Title */
    gtk_box_pack_start(GTK_BOX(vbox), make_label("All Entries", 18), FALSE, FALSE, 6);

    /* Search bar with Clear button */
    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_margin_start(search_box, 4);
    gtk_widget_set_margin_end(search_box, 4);
    gtk_box_pack_start(GTK_BOX(vbox), search_box, FALSE, FALSE, 4);

    GtkWidget *search_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(search_entry), "Search by site...");
    gtk_box_pack_start(GTK_BOX(search_box), search_entry, TRUE, TRUE, 0);

    GtkWidget *clear_btn = gtk_button_new_with_label("Clear");
    gtk_widget_set_size_request(clear_btn, 60, 32);
    gtk_box_pack_start(GTK_BOX(search_box), clear_btn, FALSE, FALSE, 0);

    /* Scrollable list container - takes all remaining space */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scroll), GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);
    
    /* Set scrolled window to 70% of window height (accounting for title, search bar, and back button) */
    int list_height = (int)(700 * 0.7);  /* 490px for 70% of 700px window */
    gtk_widget_set_size_request(scroll, -1, list_height);

    /* List container - holds the entry cards with fixed width for proper card sizing */
    GtkWidget *list_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(list_container, 880, -1);
    gtk_container_add(GTK_CONTAINER(scroll), list_container);

    /* Context for clear button (search_entry + list_container) */
    GtkWidget **clear_ctx = malloc(sizeof(GtkWidget*) * 2);
    clear_ctx[0] = search_entry;
    clear_ctx[1] = list_container;

    /* Connect search to refresh */
    g_signal_connect(search_entry, "changed", G_CALLBACK(on_search_changed), list_container);

    /* Connect Clear button to clear search and refresh */
    g_signal_connect(clear_btn, "clicked", G_CALLBACK(on_clear_search_clicked), (gpointer)clear_ctx);

    /* Initial population */
    fprintf(stderr, "DEBUG show_list_entries: calling refresh_entries_list\n");
    refresh_entries_list(list_container, "");

    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 6);
    gtk_widget_show_all(content_area);
}

/* Screen: Delete Entry */
static void on_delete_confirm(GtkWidget *btn, gpointer data) {
    (void)btn;
    const char *site = gtk_entry_get_text(GTK_ENTRY(data));
    if (!strlen(site)) { show_msg(GTK_MESSAGE_ERROR, "Error", "Enter site name"); return; }
    
    if (delete_entry(site)) {
        show_msg(GTK_MESSAGE_INFO, "Deleted", "Entry deleted");
        show_main_menu();
    } else {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Entry not found");
    }
}

static void show_delete_entry(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Delete Entry", 16), FALSE, FALSE, 5);
    
    GtkWidget *entry = make_entry(TRUE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Site name to delete");
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 5);
    gtk_widget_grab_focus(entry);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Delete", G_CALLBACK(on_delete_confirm), entry), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Edit screen - Generate password callback */
static void on_gen_for_edit_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **ctx = (GtkWidget**)data;
    GtkWidget *pass_entry = ctx[0];
    GtkWidget *len_spin = ctx[1];
    int len = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(len_spin));
    char *pass = generate_password(len);
    gtk_entry_set_text(GTK_ENTRY(pass_entry), pass);
}

/* Screen: Edit Entry - Save button handler */
static void on_edit_save_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **ctx = (GtkWidget**)data;
    const char *original_site = (const char*)ctx[0];  /* Original site for WHERE */
    GtkWidget *site_entry = ctx[1];
    GtkWidget *user_entry = ctx[2];
    GtkWidget *pass_entry = ctx[3];
    GtkWidget *notes_entry = ctx[4];
    GtkWidget *category_entry = ctx[5];
    const char *site = gtk_entry_get_text(GTK_ENTRY(site_entry));
    const char *user = gtk_entry_get_text(GTK_ENTRY(user_entry));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(pass_entry));
    const char *notes = gtk_entry_get_text(GTK_ENTRY(notes_entry));
    const char *category = gtk_entry_get_text(GTK_ENTRY(category_entry));
    
    fprintf(stderr, "DEBUG on_edit_save_clicked: original_site=%s, site=%s, user=%s, pass=%s\n", 
            original_site ? original_site : "(null)", site, user, pass);
    
    if (!strlen(site) || !strlen(user) || !strlen(pass)) {
        show_msg(GTK_MESSAGE_ERROR, "Error", "Site, username, and password required");
        free(ctx);
        return;
    }
    
    sqlite3 *db = db_open();
    if (!db) { show_msg(GTK_MESSAGE_ERROR, "Error", "Database error"); free(ctx); return; }
    
    char *encrypted = encrypt_password(pass, current_password);
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "UPDATE entries SET site=?, username=?, password_encrypted=?, notes=?, category=?, updated_at=CURRENT_TIMESTAMP WHERE site=?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, site, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, user, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, encrypted, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, notes ? notes : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, category ? category : "general", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, original_site, -1, SQLITE_TRANSIENT);
        
        fprintf(stderr, "DEBUG: Before sqlite3_step, bindings: site=%s, original_site=%s\n", site, original_site);
        int step_result = sqlite3_step(stmt);
        fprintf(stderr, "DEBUG: sqlite3_step result=%d (SQLITE_DONE=%d, SQLITE_ROW=%d, SQLITE_ERROR=%d)\n", 
                step_result, SQLITE_DONE, SQLITE_ROW, SQLITE_ERROR);
        fprintf(stderr, "DEBUG: sqlite3_changes(db)=%d\n", sqlite3_changes(db));
        
        sqlite3_finalize(stmt);
        if (step_result == SQLITE_DONE || step_result == SQLITE_ROW) {
            show_msg(GTK_MESSAGE_INFO, "Success", "Entry updated!");
            show_list_entries();
        } else {
            show_msg(GTK_MESSAGE_ERROR, "Error", "Failed to update entry");
        }
    } else {
        fprintf(stderr, "DEBUG: prepare failed: %s\n", sqlite3_errmsg(db));
        show_msg(GTK_MESSAGE_ERROR, "Error", "Failed to update entry");
    }
    sqlite3_close(db);
    free(ctx);
    g_free((gpointer)original_site);  /* Free the g_strdup copy */
}

/* Screen: Edit Entry */
static void show_edit_entry(const char *site) {
    if (!site || !strlen(site)) { show_msg(GTK_MESSAGE_ERROR, "Error", "Invalid site"); return; }
    
    sqlite3 *db = db_open();
    if (!db) { show_msg(GTK_MESSAGE_ERROR, "Error", "Database error"); return; }
    
    sqlite3_stmt *stmt;
    char *user = NULL, *pass = NULL, *url = NULL, *notes = NULL, *category = NULL;
    int found = 0;
    
    if (sqlite3_prepare_v2(db, "SELECT username, password_encrypted, url, notes, category FROM entries WHERE site=?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, site, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            found = 1;
            const char *u = (const char*)sqlite3_column_text(stmt, 0);
            const char *enc = (const char*)sqlite3_column_text(stmt, 1);
            const char *u_url = (const char*)sqlite3_column_text(stmt, 2);
            const char *n = (const char*)sqlite3_column_text(stmt, 3);
            const char *c = (const char*)sqlite3_column_text(stmt, 4);
            user = g_strdup(u ? u : "");
            pass = decrypt_password(enc, current_password);
            /* pass is a static buffer - we need to copy it before it's overwritten */
            pass = pass ? g_strdup(pass) : g_strdup("");
            url = g_strdup(u_url ? u_url : "");
            notes = g_strdup(n ? n : "");
            category = g_strdup(c ? c : "general");
            fprintf(stderr, "DEBUG show_edit_entry: category from DB = '%s'\n", category);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    
    if (!found) { show_msg(GTK_MESSAGE_ERROR, "Error", "Entry not found"); return; }
    
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Edit Entry", 16), FALSE, FALSE, 5);
    
    /* Site entry - editable */
    GtkWidget *site_entry = make_entry(TRUE);
    gtk_entry_set_text(GTK_ENTRY(site_entry), site);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new("Site"), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), site_entry, FALSE, FALSE, 5);
    
    GtkWidget *user_entry = make_entry(TRUE);
    gtk_entry_set_text(GTK_ENTRY(user_entry), user ? user : "");
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new("Username"), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), user_entry, FALSE, FALSE, 5);
    
    GtkWidget *pass_entry = make_entry(TRUE);
    gtk_entry_set_text(GTK_ENTRY(pass_entry), pass ? pass : "");
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new("Password"), FALSE, FALSE, 2);
    
    /* Length spinbox for password generation - create before pass_box */
    GtkWidget *len_spin = make_spinbox(8, 64, 16);
    
    /* Password row with visibility toggle and generate button */
    GtkWidget *pass_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(pass_box), pass_entry, TRUE, TRUE, 0);
    
    GtkWidget *toggle_btn = gtk_button_new_with_label("Show/Hide");
    gtk_widget_set_size_request(toggle_btn, 70, 30);
    g_signal_connect(toggle_btn, "clicked", G_CALLBACK(on_toggle_password_visibility), pass_entry);
    gtk_box_pack_start(GTK_BOX(pass_box), toggle_btn, FALSE, FALSE, 0);
    
    /* Generate password button for edit screen */
    GtkWidget *gen_btn = gtk_button_new_with_label("Generate");
    gtk_widget_set_size_request(gen_btn, 80, 30);
    GtkWidget **gen_ctx = malloc(sizeof(GtkWidget*) * 2);
    gen_ctx[0] = pass_entry;
    gen_ctx[1] = len_spin;
    g_signal_connect(gen_btn, "clicked", G_CALLBACK(on_gen_for_edit_clicked), gen_ctx);
    gtk_box_pack_start(GTK_BOX(pass_box), gen_btn, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(vbox), pass_box, FALSE, FALSE, 5);
    
    /* Length label and spinbox for generate */
    GtkWidget *gen_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(gen_row), gtk_label_new("Password Length:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(gen_row), len_spin, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), gen_row, FALSE, FALSE, 2);
    
    GtkWidget *notes_entry = make_entry(FALSE);
    gtk_entry_set_text(GTK_ENTRY(notes_entry), notes ? notes : "");
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new("Notes"), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), notes_entry, FALSE, FALSE, 5);
    
    /* Category row - plaintext, not encrypted - use TRUE for visibility */
    GtkWidget *category_entry = make_entry(TRUE);
    gtk_entry_set_text(GTK_ENTRY(category_entry), category ? category : "general");
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new("Category"), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(vbox), category_entry, FALSE, FALSE, 5);
    
    /* Pass original site name for WHERE clause, plus current field values */
    GtkWidget **ctx = malloc(sizeof(GtkWidget*) * 6);
    ctx[0] = (GtkWidget*)g_strdup(site);  /* Store ORIGINAL site name as COPY - survives g_free in caller */
    ctx[1] = site_entry;
    ctx[2] = user_entry;
    ctx[3] = pass_entry;
    ctx[4] = notes_entry;
    ctx[5] = category_entry;
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Save", G_CALLBACK(on_edit_save_clicked), ctx), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_list_entries), NULL), FALSE, FALSE, 5);
    
    g_free(user); g_free(pass); g_free(url); g_free(notes); g_free(category);
    gtk_widget_show_all(content_area);
}

/* Screen: Generate Password */
static void on_generate_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **vals = (GtkWidget**)data;
    if (!vals || !vals[0] || !vals[1]) { free(vals); return; }
    int len = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(vals[0]));
    char *pass = generate_password(len);
    gtk_entry_set_text(GTK_ENTRY(vals[1]), pass);
    free(vals);
}

static void show_generate(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Generate Password", 16), FALSE, FALSE, 5);
    
    GtkWidget *len_spin = make_spinbox(8, 64, 16);
    gtk_box_pack_start(GTK_BOX(vbox), len_spin, FALSE, FALSE, 5);
    
    GtkWidget *pass_entry = make_entry(TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), pass_entry, FALSE, FALSE, 5);
    
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), btn_box, FALSE, FALSE, 5);
    
    GtkWidget **vals = malloc(sizeof(GtkWidget*) * 2);
    vals[0] = len_spin;
    vals[1] = pass_entry;
    gtk_box_pack_start(GTK_BOX(btn_box), make_btn("Generate", G_CALLBACK(on_generate_clicked), vals), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(btn_box), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: Export - now includes notes field for Python compatibility */
static void on_export_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    const char *filename = gtk_entry_get_text(GTK_ENTRY(data));
    if (!strlen(filename)) { show_msg(GTK_MESSAGE_ERROR, "Error", "Enter filename"); return; }
    
    sqlite3 *db = db_open();
    if (!db) { show_msg(GTK_MESSAGE_ERROR, "Error", "Database error"); return; }
    
    FILE *f = fopen(filename, "w");
    if (!f) { sqlite3_close(db); show_msg(GTK_MESSAGE_ERROR, "Error", "Cannot create file"); return; }
    
    fprintf(f, "{\n  \"entries\": [\n");
    
    sqlite3_stmt *stmt;
    int first = 1;
    if (sqlite3_prepare_v2(db, "SELECT site, username, password_encrypted, url, notes, category FROM entries ORDER BY site", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *site = (const char*)sqlite3_column_text(stmt, 0);
            const char *user = (const char*)sqlite3_column_text(stmt, 1);
            const char *enc = (const char*)sqlite3_column_text(stmt, 2);
            const char *url = (const char*)sqlite3_column_text(stmt, 3);
            const char *notes = (const char*)sqlite3_column_text(stmt, 4);
            const char *cat = (const char*)sqlite3_column_text(stmt, 5);
            
            if (!first) fprintf(f, ",\n");
            first = 0;
            /* Export includes notes for Python version compatibility */
            fprintf(f, "    {\"site\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"url\":\"%s\",\"notes\":\"%s\",\"category\":\"%s\"}",
                     site ? site : "", user ? user : "", enc ? enc : "", url ? url : "", notes ? notes : "", cat ? cat : "general");
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Exported to %s", filename);
    show_msg(GTK_MESSAGE_INFO, "Success", msg);
    show_main_menu();
}

static void show_export(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Export to JSON", 16), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("(Encrypted, keep your password!)", 9), FALSE, FALSE, 0);
    
    GtkWidget *entry = make_entry(TRUE);
    gtk_entry_set_text(GTK_ENTRY(entry), "backup.json");
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 5);
    gtk_widget_grab_focus(entry);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Export", G_CALLBACK(on_export_clicked), entry), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: Import - parses notes field for Python compatibility */
static void on_import_clicked(GtkWidget *btn, gpointer data) {
    (void)btn;
    const char *filename = gtk_entry_get_text(GTK_ENTRY(data));
    if (!strlen(filename)) { show_msg(GTK_MESSAGE_ERROR, "Error", "Enter filename"); return; }
    
    FILE *f = fopen(filename, "r");
    if (!f) { show_msg(GTK_MESSAGE_ERROR, "Error", "Cannot open file"); return; }
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(fsize + 1);
    if (!content) { fclose(f); show_msg(GTK_MESSAGE_ERROR, "Error", "Memory error"); return; }
    size_t read_len = fread(content, 1, fsize, f);
    fclose(f);
    content[read_len] = '\0';
    
    /* Simple JSON parse - extract entries with notes support */
    int count = 0;
    char *p = content;
    while ((p = strstr(p, "\"site\":")) != NULL) {
        char site[1024] = {0}, user[1024] = {0}, pass[4096] = {0}, notes[2048] = {0};
        /* Parse site */
        if (sscanf(p, "\"site\":\"%1023[^\"]\"", site) != 1) { p++; continue; }
        /* Parse username */
        char *up = strstr(p, "\"username\":");
        if (!up || sscanf(up, "\"username\":\"%1023[^\"]\"", user) != 1) { p++; continue; }
        /* Parse password */
        char *pp = strstr(p, "\"password\":");
        if (!pp || sscanf(pp, "\"password\":\"%4095[^\"]\"", pass) != 1) { p++; continue; }
        /* Parse notes (optional) */
        char *np = strstr(p, "\"notes\":");
        if (np) sscanf(np, "\"notes\":\"%2047[^\"]\"", notes);
        
        /* Use add_entry with notes */
        if (strlen(site) && strlen(user) && strlen(pass)) {
            /* Directly call add_entry via SQL since we need to pass the already-encrypted password */
            sqlite3 *db = db_open();
            if (db) {
                char id[33] = "00000000000000000000000000000000";
                FILE *fp = fopen("/dev/urandom", "r");
                if (fp) { 
                    if (fread(id, 32, 1, fp) == 1) {
                        for (int i = 0; i < 32; i++) sprintf(id + i, "%02x", (unsigned char)id[i]);
                        id[32] = '\0';
                    }
                    fclose(fp); 
                }
                
                sqlite3_stmt *stmt;
                if (sqlite3_prepare_v2(db, "INSERT INTO entries (id, site, username, password_encrypted, notes) VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 2, site, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 3, user, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 4, pass, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 5, notes, -1, SQLITE_STATIC);
                    if (sqlite3_step(stmt) == SQLITE_DONE) count++;
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
        p++;
    }
    free(content);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Imported %d entries", count);
    show_msg(GTK_MESSAGE_INFO, "Success", msg);
    show_main_menu();
}

static void show_import(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Import from JSON", 16), FALSE, FALSE, 5);
    
    GtkWidget *entry = make_entry(TRUE);
    gtk_entry_set_text(GTK_ENTRY(entry), "backup.json");
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 5);
    gtk_widget_grab_focus(entry);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Import", G_CALLBACK(on_import_clicked), entry), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 5);
    
    gtk_widget_show_all(content_area);
}

/* Screen: About */
static void show_about(void) {
    clear_content();
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Password Manager", 20), FALSE, FALSE, 10);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Version 1.1 (C GTK3)", 12), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(""), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Secure password storage", 11), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("AES-256-GCM encryption", 10), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(""), FALSE, FALSE, 10);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("Created By J~Net 2026", 12), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), make_label("jnetai.com", 10), FALSE, FALSE, 5);
    
    gtk_box_pack_start(GTK_BOX(vbox), make_btn("Back", G_CALLBACK(show_main_menu), NULL), FALSE, FALSE, 10);
    gtk_widget_show_all(content_area);
}

/* Lock */
static void lock_and_login(void) {
    memset(current_password, 0, sizeof(current_password));
    is_logged_in = 0;
    g_add_pass_entry = NULL;
    show_login_screen();
}

/* Main */
int main(int argc, char *argv[]) {
    
    gtk_init(&argc, &argv);
    srand(time(NULL));
    init_db_path();
    db_init();
    
    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "Password Manager");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 700, 550);
    gtk_container_set_border_width(GTK_CONTAINER(main_window), 10);
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    content_area = gtk_fixed_new();
    gtk_container_add(GTK_CONTAINER(main_window), content_area);
    
    if (db_has_password())
        show_login_screen();
    else
        show_setup_screen();
    
    gtk_widget_show_all(main_window);
    gtk_main();
    return 0;
}
