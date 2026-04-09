package com.passwordmanager.app

import android.app.Application
import com.passwordmanager.app.db.AppDatabase

class PasswordManagerApp : Application() {
    
    val database: AppDatabase by lazy {
        AppDatabase.getDatabase(this)
    }
    
    override fun onCreate() {
        super.onCreate()
    }
}
