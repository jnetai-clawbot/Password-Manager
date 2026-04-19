package com.passwordmanager.app

import android.app.Application
import com.passwordmanager.app.db.EntryDatabase

class PasswordManagerApp : Application() {
    
    val database: EntryDatabase by lazy {
        EntryDatabase.getInstance(this)
    }
    
    override fun onCreate() {
        super.onCreate()
    }
}