package com.passwordmanager.app

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.passwordmanager.app.databinding.ItemEntryBinding
import com.passwordmanager.app.db.Entry

class EntriesAdapter(
    private val onViewClick: (Entry) -> Unit,
    private val onCopyClick: (Entry) -> Unit
) : ListAdapter<Entry, EntriesAdapter.EntryViewHolder>(EntryDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EntryViewHolder {
        val binding = ItemEntryBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return EntryViewHolder(binding)
    }

    override fun onBindViewHolder(holder: EntryViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class EntryViewHolder(
        private val binding: ItemEntryBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(entry: Entry) {
            binding.tvSite.text = entry.site
            binding.tvUsername.text = entry.username
            binding.tvCategory.text = entry.category
            
            binding.root.setOnClickListener { onViewClick(entry) }
            binding.btnCopy.setOnClickListener { onCopyClick(entry) }
            binding.btnCopyUsername.setOnClickListener { 
                val clipboard = binding.root.context.getSystemService(android.content.ClipboardManager::class.java)
                val clip = android.content.ClipData.newPlainText("Username", entry.username)
                clipboard.setPrimaryClip(clip)
                android.widget.Toast.makeText(binding.root.context, "Username copied", android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    }

    class EntryDiffCallback : DiffUtil.ItemCallback<Entry>() {
        override fun areItemsTheSame(oldItem: Entry, newItem: Entry): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: Entry, newItem: Entry): Boolean {
            return oldItem == newItem
        }
    }
}
