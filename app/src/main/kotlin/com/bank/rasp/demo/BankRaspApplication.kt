package com.bank.rasp.demo

import android.app.Application
import com.bank.rasp.demo.rasp.NativeSelfCheck

/**
 * Application：在任何第三方 SDK 初始化之前尽早建立 native 自校验基线，
 * 缩小「注入发生在基线建立之前」的时间窗（生产中可进一步把基线上移到 attachBaseContext）。
 */
class BankRaspApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        runCatching { NativeSelfCheck(this).establishBaselines() }
    }
}
