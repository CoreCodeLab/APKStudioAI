
rule Android_Trojan_Generic {
    meta:
        description = "Generic Android trojan indicators"
        author = "APKStudioAI"
        severity = "high"
    strings:
        $send_sms = "sendTextMessage" ascii
        $device_id = "getDeviceId" ascii
        $runtime_exec = "Runtime.getRuntime().exec" ascii
        $dex_loader = "DexClassLoader" ascii
        $crypto = "Cipher.getInstance" ascii
        $http = "HttpURLConnection" ascii
        $websocket = "WebSocket" ascii
        $reflection = "Class.forName" ascii
        $accessibility = "AccessibilityService" ascii
        $vpn = "VpnService" ascii
    condition:
        3 of them
}

rule Android_Spyware {
    meta:
        description = "Android spyware indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $record_audio = "MediaRecorder" ascii
        $camera = "Camera.open" ascii
        $location = "LocationManager" ascii
        $contacts = "ContactsContract" ascii
        $sms_read = "content://sms" ascii
        $call_log = "CallLog.Calls" ascii
        $keylogger = "onKeyDown" ascii
        $screen_capture = "MediaProjection" ascii
    condition:
        2 of them
}

rule Android_Ransomware {
    meta:
        description = "Android ransomware indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $encrypt = "Cipher.init" ascii
        $encrypt2 = "Cipher.doFinal" ascii
        $file_enum = "listFiles" ascii
        $delete = "delete" ascii
        $lock_screen = "DevicePolicyManager.lockNow" ascii
        $reset_pass = "DevicePolicyManager.resetPassword" ascii
        $wipe = "DevicePolicyManager.wipeData" ascii
        $bitcoin = "bitcoin" ascii nocase
        $ransom = "ransom" ascii nocase
    condition:
        3 of them
}

rule Android_Banking_Trojan {
    meta:
        description = "Android banking trojan indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $overlay = "SYSTEM_ALERT_WINDOW" ascii
        $accessibility = "AccessibilityService" ascii
        $keylog = "onAccessibilityEvent" ascii
        $sms_intercept = "abortBroadcast" ascii
        $ussd = "USSD" ascii
        $bank = "bank" ascii nocase
        $login = "login" ascii nocase
        $credential = "credential" ascii nocase
        $webview = "addJavascriptInterface" ascii
    condition:
        3 of them
}

rule Android_Dropper {
    meta:
        description = "Android dropper/downloader indicators"
        author = "APKStudioAI"
        severity = "high"
    strings:
        $download = "download" ascii
        $exec = "exec" ascii
        $load_dex = "loadDex" ascii
        $dex_class_loader = "DexClassLoader" ascii
        $path_class_loader = "PathClassLoader" ascii
        $write_file = "FileOutputStream" ascii
        $chmod = "chmod" ascii
        $install = "installPackage" ascii
    condition:
        3 of them
}

rule Android_Adware {
    meta:
        description = "Android adware indicators"
        author = "APKStudioAI"
        severity = "medium"
    strings:
        $ad_sdk = "AdView" ascii
        $interstitial = "InterstitialAd" ascii
        $rewarded = "RewardedAd" ascii
        $ad_request = "AdRequest" ascii
        $ad_mob = "AdMob" ascii
        $ad_size = "AdSize" ascii
        $load_ad = "loadAd" ascii
    condition:
        2 of them
}

rule Android_Root_Exploit {
    meta:
        description = "Android root exploit indicators"
        author = "APKStudioAI"
        severity = "critical"
    strings:
        $su = "/system/bin/su" ascii
        $su2 = "/system/xbin/su" ascii
        $root = "ROOT" ascii
        $exploit = "exploit" ascii nocase
        $dirtycow = "dirtycow" ascii nocase
        $cve = "CVE-" ascii
        $kernel = "kernel" ascii
        $privilege = "privilege" ascii nocase
        $escalation = "escalation" ascii nocase
    condition:
        2 of them
}

rule Suspicious_Native_Code {
    meta:
        description = "Suspicious native code patterns"
        author = "APKStudioAI"
        severity = "high"
    strings:
        $jni_onload = "JNI_OnLoad" ascii
        $system_load = "System.loadLibrary" ascii
        $system_load2 = "System.load" ascii
        $dlopen = "dlopen" ascii
        $dlsym = "dlsym" ascii
        $mprotect = "mprotect" ascii
        $mmap = "mmap" ascii
        $ptrace = "ptrace" ascii
        $anti_debug = "anti_debug" ascii nocase
    condition:
        2 of them
}
