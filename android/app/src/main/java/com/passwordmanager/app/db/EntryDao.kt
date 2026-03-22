package com.passwordmanager.app.db

import androidx.room.*

@Dao
interface EntryDao {
    @Query("SELECT * FROM entries ORDER BY site ASC")
    fun getAll(): List<Entry>

    @Query("SELECT * FROM entries WHERE id = :id")
    fun getById(id: String): Entry?

    @Query("SELECT * FROM entries WHERE site = :site")
    fun getBySite(site: String): Entry?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(entry: Entry)

    @Update
    fun update(entry: Entry)

    @Delete
    fun delete(entry: Entry)

    @Query("DELETE FROM entries WHERE id = :id")
    fun deleteById(id: String)
}
