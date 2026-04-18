package com.echworkers.android.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.echworkers.android.model.EWPNode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class NodeRepository(context: Context) {
    
    companion object {
        private const val TAG = "NodeRepository"
        private const val PREFS_NAME = "nodes"
        private const val ENCRYPTED_PREFS_NAME = "nodes_encrypted" // P1-25: new encrypted storage
        private const val KEY_NODES = "nodes_json"
        private const val KEY_SELECTED_NODE_ID = "selected_node_id"
        private const val KEY_MIGRATION_DONE = "migration_done_v1"
    }
    
    // P1-25: Use EncryptedSharedPreferences to protect credentials at rest
    private val prefs: SharedPreferences = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        
        EncryptedSharedPreferences.create(
            context,
            ENCRYPTED_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (e: Exception) {
        Log.e(TAG, "Failed to create EncryptedSharedPreferences, falling back to plain", e)
        // Fallback to plain SharedPreferences if encryption fails (e.g., KeyStore issues)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    
    private val json = Json { 
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    private val _nodes = MutableStateFlow<List<EWPNode>>(emptyList())
    val nodes: StateFlow<List<EWPNode>> = _nodes.asStateFlow()
    
    private val _selectedNode = MutableStateFlow<EWPNode?>(null)
    val selectedNode: StateFlow<EWPNode?> = _selectedNode.asStateFlow()
    
    init {
        // P1-25: Migrate from old plain SharedPreferences to encrypted storage
        migrateFromPlainPrefs(context)
        loadNodes()
    }
    
    fun addNode(node: EWPNode) {
        val updated = _nodes.value + node
        _nodes.value = updated
        saveNodes(updated)
        Log.i(TAG, "Node added: ${node.name}")
    }
    
    fun updateNode(node: EWPNode) {
        val updated = _nodes.value.map { 
            if (it.id == node.id) node else it 
        }
        _nodes.value = updated
        saveNodes(updated)
        
        if (_selectedNode.value?.id == node.id) {
            _selectedNode.value = node
            saveSelectedNodeId(node.id)
        }
        
        Log.i(TAG, "Node updated: ${node.name}")
    }
    
    fun deleteNode(nodeId: String) {
        val updated = _nodes.value.filter { it.id != nodeId }
        _nodes.value = updated
        saveNodes(updated)
        
        if (_selectedNode.value?.id == nodeId) {
            _selectedNode.value = updated.firstOrNull()
            saveSelectedNodeId(_selectedNode.value?.id)
        }
        
        Log.i(TAG, "Node deleted: $nodeId")
    }
    
    fun selectNode(nodeId: String) {
        val node = _nodes.value.find { it.id == nodeId }
        _selectedNode.value = node
        saveSelectedNodeId(nodeId)
        Log.i(TAG, "Node selected: ${node?.name}")
    }
    
    fun getNodeById(nodeId: String): EWPNode? {
        return _nodes.value.find { it.id == nodeId }
    }
    
    private fun saveNodes(nodes: List<EWPNode>) {
        try {
            val jsonString = json.encodeToString(nodes)
            prefs.edit().putString(KEY_NODES, jsonString).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save nodes", e)
        }
    }
    
    private fun loadNodes() {
        try {
            val jsonString = prefs.getString(KEY_NODES, null)
            if (jsonString != null) {
                val nodes = json.decodeFromString<List<EWPNode>>(jsonString)
                _nodes.value = nodes
                Log.i(TAG, "Loaded ${nodes.size} nodes")
                
                val selectedId = prefs.getString(KEY_SELECTED_NODE_ID, null)
                if (selectedId != null) {
                    _selectedNode.value = nodes.find { it.id == selectedId }
                } else {
                    _selectedNode.value = nodes.firstOrNull()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load nodes", e)
        }
    }
    
    private fun saveSelectedNodeId(nodeId: String?) {
        prefs.edit().putString(KEY_SELECTED_NODE_ID, nodeId).apply()
    }
}

    
    /**
     * P1-25: Migrate data from old plain SharedPreferences to encrypted storage.
     * This runs once on first launch after upgrade. After successful migration,
     * the old plain prefs file is deleted to prevent credential leakage.
     */
    private fun migrateFromPlainPrefs(context: Context) {
        // Check if migration already done
        if (prefs.getBoolean(KEY_MIGRATION_DONE, false)) {
            return
        }
        
        try {
            val oldPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val oldNodesJson = oldPrefs.getString(KEY_NODES, null)
            val oldSelectedId = oldPrefs.getString(KEY_SELECTED_NODE_ID, null)
            
            if (oldNodesJson != null) {
                Log.i(TAG, "Migrating nodes from plain to encrypted storage...")
                
                // Copy data to encrypted prefs
                prefs.edit()
                    .putString(KEY_NODES, oldNodesJson)
                    .putString(KEY_SELECTED_NODE_ID, oldSelectedId)
                    .putBoolean(KEY_MIGRATION_DONE, true)
                    .apply()
                
                // Delete old plain prefs to prevent credential leakage
                oldPrefs.edit().clear().apply()
                
                // Try to delete the actual file (requires API 24+)
                try {
                    context.deleteSharedPreferences(PREFS_NAME)
                    Log.i(TAG, "Migration complete, old plain prefs deleted")
                } catch (e: Exception) {
                    Log.w(TAG, "Could not delete old prefs file (API < 24?)", e)
                }
            } else {
                // No old data to migrate, just mark as done
                prefs.edit().putBoolean(KEY_MIGRATION_DONE, true).apply()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Migration failed, will retry on next launch", e)
        }
    }
