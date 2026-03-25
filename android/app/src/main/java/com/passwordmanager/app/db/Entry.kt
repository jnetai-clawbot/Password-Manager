package com.passwordmanager.app.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "entries")
data class Entry(
    @PrimaryKey
    val id: String,
    val site: String,
    val username: String,
    val passwordEncrypted: String,
    val url: String = "",
    val notes: String = "",
    val category: String = "general",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)
