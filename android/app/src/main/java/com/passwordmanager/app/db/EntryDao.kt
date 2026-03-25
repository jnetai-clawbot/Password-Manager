package com.passwordmanager.app.db

import androidx.room.*

@Dao
interface EntryDao {
    @Query("SELECT * FROM entries ORDER BY site ASC")
    fun getAll(): List<Entry>

    @Query("SELECT * FROM entries WHERE site LIKE '%' || :query || '%' OR username LIKE '%' || :query || '%' OR url LIKE '%' || :query || '%' ORDER BY site ASC")
    fun search(query: String): List<Entry>

    @Query("SELECT * FROM entries WHERE category = :category ORDER BY site ASC")
    fun getByCategory(category: String): List<Entry>

    @Query("SELECT * FROM entries WHERE site LIKE '%' || :query || '%' OR username LIKE '%' || :query || '%' OR url LIKE '%' || :query || '%' AND category = :category ORDER BY site ASC")
    fun searchInCategory(query: String, category: String): List<Entry>

    @Query("SELECT DISTINCT category FROM entries ORDER BY category ASC")
    fun getAllCategories(): List<String>

    @Query("SELECT * FROM entries WHERE id = :id")
    fun getById(id: String): Entry?

    @Query("SELECT * FROM entries WHERE site = :site")
    fun getBySite(site: String): Entry?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(entry: Entry)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertAll(entries: List<Entry>)

    @Update
    fun update(entry: Entry)

    @Delete
    fun delete(entry: Entry)

    @Query("DELETE FROM entries WHERE id = :id")
    fun deleteById(id: String)

    @Query("DELETE FROM entries")
    fun deleteAll()
}
