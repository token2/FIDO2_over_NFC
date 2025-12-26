package pl.lebihan.authnkey

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

class CredentialsDialogContent(
    context: Context,
    credentials: List<CredentialItem>,
    initialRemaining: Int,
    onDelete: (CredentialItem) -> Unit
) {
    private var remainingSlots = initialRemaining

    val view: View = LayoutInflater.from(context).inflate(R.layout.dialog_credentials, null)

    private val statsText: TextView = view.findViewById(R.id.statsText)
    private val recyclerView: RecyclerView = view.findViewById(R.id.credentialList)
    private val emptyState: View = view.findViewById(R.id.emptyState)
    private val adapter: CredentialsAdapter = CredentialsAdapter(credentials, onDelete)

    init {
        recyclerView.layoutManager = LinearLayoutManager(context)
        recyclerView.adapter = adapter

        updateVisibility()
        updateStats()
    }

    fun notifyDeleted(item: CredentialItem) {
        adapter.removeItem(item)
        remainingSlots++
        updateStats()
        updateVisibility()
    }

    private fun updateStats() {
        statsText.text = view.context.getString(
            R.string.credentials_stats,
            adapter.count,
            remainingSlots
        )
    }

    private fun updateVisibility() {
        if (adapter.count == 0) {
            recyclerView.visibility = View.GONE
            emptyState.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyState.visibility = View.GONE
        }
    }
}
