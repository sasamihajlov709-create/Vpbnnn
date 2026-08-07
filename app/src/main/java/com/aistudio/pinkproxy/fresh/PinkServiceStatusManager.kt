package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object PinkServiceStatusManager {
    private val _customServices = MutableStateFlow<List<Pair<String, String>>>(emptyList())
    val customServices: StateFlow<List<Pair<String, String>>> = _customServices.asStateFlow()

    fun loadCustomServices(context: Context) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        val saved = prefs.getString("custom_services", "") ?: ""
        if (saved.isNotEmpty()) {
            val list = saved.split(";").mapNotNull {
                val parts = it.split("|")
                if (parts.size == 2) Pair(parts[0], parts[1]) else null
            }
            _customServices.value = list
        } else {
            _customServices.value = emptyList()
        }
    }

    fun addCustomService(context: Context, name: String, url: String) {
        val current = _customServices.value.toMutableList()
        if (current.none { it.first == name }) {
            current.add(Pair(name, url))
            _customServices.value = current
            saveCustomServices(context, current)
        }
    }

    fun removeCustomService(context: Context, name: String) {
        val current = _customServices.value.filter { it.first != name }
        _customServices.value = current
        saveCustomServices(context, current)
    }

    private fun saveCustomServices(context: Context, list: List<Pair<String, String>>) {
        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
        val serialized = list.joinToString(";") { "${it.first}|${it.second}" }
        prefs.edit { putString("custom_services", serialized) }
    }

    fun getDefaultServices() = listOf(
        Pair("YouTube", "https://www.youtube.com"),
        Pair("YT Video Stream", "https://redirector.googlevideo.com/report_mapping"),
        Pair("Telegram", "https://t.me"),
        Pair("Google", "https://www.google.com"),
        Pair("Instagram", "https://www.instagram.com"),
        Pair("X (Twitter)", "https://x.com"),
        Pair("ChatGPT", "https://chatgpt.com"),
        Pair("Discord", "https://discord.com"),
        Pair("GitHub", "https://github.com"),
        Pair("VK (Control)", "https://vk.com"),
        Pair("Yandex (Control)", "https://ya.ru"),
        Pair("Mail.ru (Control)", "https://mail.ru")
    )
}
