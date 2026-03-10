package com.svcmonitor.app

import android.annotation.SuppressLint
import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

class EventAdapter(
    private val onItemClick: (SvcEvent) -> Unit
) : ListAdapter<SvcEvent, EventAdapter.VH>(DIFF) {

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<SvcEvent>() {
            override fun areItemsTheSame(a: SvcEvent, b: SvcEvent) = a.seq == b.seq
            override fun areContentsTheSame(a: SvcEvent, b: SvcEvent) = a == b
        }

        // category colors
        private val CAT_COLORS = mapOf(
            "File I/O" to 0xFF1565C0.toInt(),       // blue
            "Filesystem" to 0xFF00838F.toInt(),      // teal
            "Network" to 0xFF6A1B9A.toInt(),         // purple
            "Process" to 0xFFC62828.toInt(),          // red
            "Memory" to 0xFF2E7D32.toInt(),           // green
            "Security" to 0xFFE65100.toInt(),         // deep orange
            "Signal" to 0xFFAD1457.toInt(),           // pink
            "IPC" to 0xFF4527A0.toInt(),              // deep purple
        )
    }

    private fun getCategoryForNr(nr: Int): String {
        for ((cat, nrs) in SyscallInfo.CATEGORIES) {
            if (nr in nrs) return cat
        }
        return "Other"
    }

    private fun getCategoryColor(cat: String): Int {
        return CAT_COLORS[cat] ?: 0xFF546E7A.toInt()  // blue grey fallback
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_event, parent, false)
        return VH(v)
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: VH, position: Int) {
        val ev = getItem(position)
        val cat = getCategoryForNr(ev.nr)
        val color = getCategoryColor(cat)

        holder.tvSeq.text = "#${ev.seq}"
        holder.tvSyscall.text = ev.name
        holder.tvSyscall.setTextColor(color)
        holder.tvCategory.text = cat
        holder.tvCategory.setTextColor(color)
        holder.tvPidComm.text = "${ev.comm} (${ev.pid})"
        holder.tvUid.text = "UID:${ev.uid}"

        // caller info
        val callerText = when {
            ev.caller.isNotEmpty() && ev.caller != "?" -> ev.caller
            ev.callerAddr.isNotEmpty() -> "0x${ev.callerAddr}"
            else -> ""
        }
        if (callerText.isNotEmpty()) {
            holder.tvCaller.visibility = View.VISIBLE
            holder.tvCaller.text = callerText
        } else {
            holder.tvCaller.visibility = View.GONE
        }

        // description (deep parsed args)
        if (ev.desc.isNotEmpty()) {
            holder.tvDesc.visibility = View.VISIBLE
            holder.tvDesc.text = ev.desc
        } else {
            holder.tvDesc.visibility = View.GONE
        }

        // fd path
        if (ev.fdPath.isNotEmpty()) {
            holder.tvFdPath.visibility = View.VISIBLE
            holder.tvFdPath.text = ev.fdPath
        } else {
            holder.tvFdPath.visibility = View.GONE
        }

        // category indicator bar
        holder.categoryBar.setBackgroundColor(color)

        holder.itemView.setOnClickListener { onItemClick(ev) }
    }

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val tvSeq: TextView = v.findViewById(R.id.tvSeq)
        val tvSyscall: TextView = v.findViewById(R.id.tvSyscall)
        val tvCategory: TextView = v.findViewById(R.id.tvCategory)
        val tvPidComm: TextView = v.findViewById(R.id.tvPidComm)
        val tvUid: TextView = v.findViewById(R.id.tvUid)
        val tvCaller: TextView = v.findViewById(R.id.tvCaller)
        val tvDesc: TextView = v.findViewById(R.id.tvDesc)
        val tvFdPath: TextView = v.findViewById(R.id.tvFdPath)
        val categoryBar: View = v.findViewById(R.id.categoryBar)
    }
}
