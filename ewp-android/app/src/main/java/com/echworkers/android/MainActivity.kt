package com.echworkers.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.echworkers.android.ui.navigation.EWPNavHost
import com.echworkers.android.ui.theme.EWPTheme
import com.echworkers.android.viewmodel.MainViewModel

class MainActivity : ComponentActivity() {
    
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel?.connect()
        }
    }
    
    private var viewModel: MainViewModel? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            val vm: MainViewModel = viewModel()
            viewModel = vm
            
            EWPTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    EWPNavHost(
                        viewModel = vm,
                        onRequestVpnPermission = ::requestVpnPermission
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // 每次 app 回到前台时刷新应用列表，确保新安装/卸载的应用能被感知
        viewModel?.loadApps()
    }
    
    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            viewModel?.connect()
        }
    }
}
