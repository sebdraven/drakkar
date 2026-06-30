//! Catalogue de détection embarqué : mapping technique MITRE -> logique de
//! détection statique (`features:` YAML). C'est la contribution de Drakkar,
//! versionnée avec le code. Les métadonnées (nom, tactique, plateformes) viennent
//! du STIX téléchargé ; ce catalogue ne fournit QUE le bloc `features`.
//!
//! Toute technique absente de ce catalogue est marquée `out-of-scope` à la
//! génération (couverture exhaustive, non-détection documentée).

/// Retourne le bloc `features:` (corps YAML) pour un ID de technique, ou None
/// si la technique n'est pas détectable statiquement.
pub fn detection_for(id: &str) -> Option<&'static str> {
    match id {
        "T1398" => Some(
            r#"  or:
    - intent-action: android.intent.action.BOOT_COMPLETED
    - permission: android.permission.RECEIVE_BOOT_COMPLETED"#,
        ),
        "T1404" => Some(
            r#"  or:
    - string: /system/bin/su
    - string: supersu
    - api: Ljava/lang/Runtime;->exec"#,
        ),
        "T1406" => Some(
            r#"  or:
    - api: Ljavax/crypto/Cipher;->doFinal
    - api: Ldalvik/system/DexClassLoader;-><init>
    - string: AES/CBC/PKCS5Padding"#,
        ),
        "T1406.002" => Some(
            r#"  or:
    - api: Ldalvik/system/DexClassLoader;-><init>
    - api: Ldalvik/system/InMemoryDexClassLoader;-><init>"#,
        ),
        "T1407" => Some(
            r#"  or:
    - api: Ldalvik/system/DexClassLoader;->loadClass
    - api: Ldalvik/system/PathClassLoader;-><init>
    - api: Ljava/lang/Runtime;->exec"#,
        ),
        "T1409" => Some(
            r#"  or:
    - api: Landroid/content/Context;->getExternalFilesDir
    - api: Landroid/app/Application;->getFilesDir
    - api: Landroid/content/Context;->openFileInput"#,
        ),
        "T1414" => Some(
            r#"  and:
    - or:
        - api: Landroid/content/ClipboardManager;->getPrimaryClip
        - api: Landroid/content/ClipboardManager;->getText
    - api: Landroid/content/ClipboardManager;->addPrimaryClipChangedListener"#,
        ),
        "T1417" => Some(
            r#"  or:
    - permission: android.permission.BIND_ACCESSIBILITY_SERVICE
    - accessibility-service: true
    - api: Landroid/inputmethodservice/InputMethodService;->onStartInput"#,
        ),
        "T1417.001" => Some(
            r#"  and:
    - accessibility-service: true
    - api: Landroid/view/accessibility/AccessibilityEvent;->getText"#,
        ),
        "T1417.002" => Some(
            r#"  and:
    - accessibility-service: true
    - api: Landroid/view/accessibility/AccessibilityNodeInfo;->getText"#,
        ),
        "T1418" => Some(
            r#"  or:
    - api: Landroid/content/pm/PackageManager;->getInstalledPackages
    - api: Landroid/content/pm/PackageManager;->getInstalledApplications"#,
        ),
        "T1418.001" => Some(
            r#"  and:
    - api: Landroid/content/pm/PackageManager;->getInstalledPackages
    - or:
        - string: com.avast
        - string: com.lookout
        - string: antivirus"#,
        ),
        "T1420" => Some(
            r#"  or:
    - api: Ljava/io/File;->listFiles
    - api: Landroid/os/Environment;->getExternalStorageDirectory"#,
        ),
        "T1421" => Some(
            r#"  or:
    - api: Landroid/net/ConnectivityManager;->getAllNetworkInfo
    - permission: android.permission.ACCESS_NETWORK_STATE"#,
        ),
        "T1422" => Some(
            r#"  or:
    - api: Landroid/net/wifi/WifiManager;->getConnectionInfo
    - permission: android.permission.ACCESS_NETWORK_STATE"#,
        ),
        "T1422.002" => Some(
            r#"  and:
    - permission: android.permission.ACCESS_WIFI_STATE
    - api: Landroid/net/wifi/WifiManager;->getScanResults"#,
        ),
        "T1424" => Some(
            r#"  or:
    - api: Landroid/app/ActivityManager;->getRunningAppProcesses
    - api: Landroid/app/ActivityManager;->getRunningServices"#,
        ),
        "T1426" => Some(
            r#"  or:
    - api: Landroid/os/Build;->MODEL
    - api: Landroid/telephony/TelephonyManager;->getDeviceId
    - api: Landroid/provider/Settings$Secure;->getString"#,
        ),
        "T1429" => Some(
            r#"  and:
    - permission: android.permission.RECORD_AUDIO
    - or:
        - api: Landroid/media/MediaRecorder;->start
        - api: Landroid/media/AudioRecord;->startRecording"#,
        ),
        "T1430" => Some(
            r#"  and:
    - or:
        - permission: android.permission.ACCESS_FINE_LOCATION
        - permission: android.permission.ACCESS_COARSE_LOCATION
        - permission: android.permission.ACCESS_BACKGROUND_LOCATION
    - or:
        - api: Landroid/location/LocationManager;->getLastKnownLocation
        - api: Landroid/location/LocationManager;->requestLocationUpdates
        - api: Lcom/google/android/gms/location/FusedLocationProviderClient;->getLastLocation"#,
        ),
        "T1437" => Some(
            r#"  or:
    - api: Ljava/net/HttpURLConnection;->connect
    - api: Lokhttp3/OkHttpClient;->newCall
    - api: Lorg/apache/http/client/HttpClient;->execute"#,
        ),
        "T1437.001" => Some(
            r#"  or:
    - api: Ljava/net/HttpURLConnection;->connect
    - api: Lokhttp3/Request$Builder;->build"#,
        ),
        "T1453" => Some(
            r#"  or:
    - accessibility-service: true
    - permission: android.permission.BIND_ACCESSIBILITY_SERVICE"#,
        ),
        "T1481.001" => Some(
            r#"  or:
    - string: pastebin.com
    - string: github.com
    - string: docs.google.com"#,
        ),
        "T1481.002" => Some(
            r#"  or:
    - string: firebaseio.com
    - string: firebasedatabase"#,
        ),
        "T1512" => Some(
            r#"  and:
    - permission: android.permission.CAMERA
    - or:
        - api: Landroid/hardware/camera2/CameraManager;->openCamera
        - api: Landroid/hardware/Camera;->open
        - api: Landroidx/camera/core/ImageCapture;->takePicture"#,
        ),
        "T1513" => Some(
            r#"  or:
    - api: Landroid/media/projection/MediaProjectionManager;->createScreenCaptureIntent
    - api: Landroid/media/projection/MediaProjection;->createVirtualDisplay
    - api: Landroid/view/View;->getDrawingCache"#,
        ),
        "T1516" => Some(
            r#"  and:
    - accessibility-service: true
    - or:
        - api: Landroid/accessibilityservice/AccessibilityService;->performGlobalAction
        - api: Landroid/accessibilityservice/AccessibilityService;->dispatchGesture
        - api: Landroid/view/accessibility/AccessibilityNodeInfo;->performAction"#,
        ),
        "T1517" => Some(
            r#"  and:
    - or:
        - permission: android.permission.BIND_NOTIFICATION_LISTENER_SERVICE
        - service: NotificationListenerService
    - or:
        - api: Landroid/service/notification/NotificationListenerService;->onNotificationPosted
        - api: Landroid/service/notification/StatusBarNotification;->getNotification"#,
        ),
        "T1521" => Some(
            r#"  or:
    - api: Ljavax/crypto/Cipher;->getInstance
    - api: Ljavax/net/ssl/SSLSocket;->startHandshake"#,
        ),
        "T1521.001" => Some(
            r#"  and:
    - api: Ljavax/crypto/Cipher;->getInstance
    - or:
        - string: AES
        - string: DES"#,
        ),
        "T1521.003" => Some(
            r#"  or:
    - api: Ljavax/net/ssl/SSLContext;->init
    - string: sha256/"#,
        ),
        "T1532" => Some(
            r#"  or:
    - api: Ljava/util/zip/ZipOutputStream;->putNextEntry
    - api: Ljava/util/zip/GZIPOutputStream;-><init>
    - api: Landroid/util/Base64;->encode"#,
        ),
        "T1533" => Some(
            r#"  or:
    - api: Landroid/os/Environment;->getExternalStorageDirectory
    - api: Landroid/content/Context;->getFilesDir
    - permission: android.permission.READ_EXTERNAL_STORAGE"#,
        ),
        "T1541" => Some(
            r#"  or:
    - api: Landroid/app/Service;->startForeground
    - api: Landroid/app/Notification$Builder;->setOngoing"#,
        ),
        "T1544" => Some(
            r#"  or:
    - api: Landroid/app/DownloadManager;->enqueue
    - api: Ljava/net/URL;->openStream"#,
        ),
        "T1575" => Some(
            r#"  or:
    - api: Ljava/lang/System;->loadLibrary
    - api: Ljava/lang/Runtime;->loadLibrary"#,
        ),
        "T1582" => Some(
            r#"  and:
    - or:
        - permission: android.permission.SEND_SMS
        - permission: android.permission.RECEIVE_SMS
    - or:
        - api: Landroid/telephony/SmsManager;->sendTextMessage
        - api: Landroid/telephony/SmsManager;->sendMultipartTextMessage"#,
        ),
        "T1603" => Some(
            r#"  or:
    - api: Landroid/app/job/JobScheduler;->schedule
    - api: Landroid/app/AlarmManager;->setRepeating
    - string: androidx.work.WorkManager"#,
        ),
        "T1616" => Some(
            r#"  and:
    - or:
        - permission: android.permission.READ_PHONE_STATE
        - permission: android.permission.CALL_PHONE
        - permission: android.permission.ANSWER_PHONE_CALLS
    - or:
        - api: Landroid/telephony/TelephonyManager;->listen
        - api: Landroid/telecom/TelecomManager;->endCall"#,
        ),
        "T1617" => Some(
            r#"  or:
    - string: de.robv.android.xposed
    - string: libsubstrate
    - api: Ljava/lang/reflect/Method;->invoke"#,
        ),
        "T1623" => Some(
            r#"  or:
    - api: Ljava/lang/Runtime;->exec
    - api: Ljava/lang/ProcessBuilder;->start"#,
        ),
        "T1623.001" => Some(
            r#"  and:
    - api: Ljava/lang/Runtime;->exec
    - or:
        - string: /system/bin/sh
        - string: su"#,
        ),
        "T1624.001" => Some(
            r#"  or:
    - intent-action: android.intent.action.BOOT_COMPLETED
    - intent-action: android.intent.action.SCREEN_ON
    - api: Landroid/content/BroadcastReceiver;->onReceive"#,
        ),
        "T1626.001" => Some(
            r#"  or:
    - permission: android.permission.BIND_DEVICE_ADMIN
    - api: Landroid/app/admin/DevicePolicyManager;->isAdminActive"#,
        ),
        "T1628.001" => Some(
            r#"  or:
    - api: Landroid/content/pm/PackageManager;->setComponentEnabledSetting
    - string: android.intent.category.LAUNCHER"#,
        ),
        "T1629.001" => Some(
            r#"  or:
    - permission: android.permission.BIND_DEVICE_ADMIN
    - api: Landroid/app/admin/DevicePolicyManager;->isAdminActive"#,
        ),
        "T1629.003" => Some(
            r#"  or:
    - api: Landroid/app/admin/DevicePolicyManager;->lockNow
    - permission: android.permission.BIND_DEVICE_ADMIN"#,
        ),
        "T1630.001" => Some(
            r#"  or:
    - api: Landroid/content/pm/PackageManager;->deletePackage
    - intent-action: android.intent.action.DELETE"#,
        ),
        "T1630.002" => Some(
            r#"  or:
    - api: Ljava/io/File;->delete
    - api: Landroid/content/Context;->deleteFile"#,
        ),
        "T1633.001" => Some(
            r#"  or:
    - string: /proc/cpuinfo
    - string: ro.build.fingerprint
    - api: Landroid/os/Build;->FINGERPRINT"#,
        ),
        "T1635" => Some(
            r#"  or:
    - api: Landroid/webkit/CookieManager;->getCookie
    - api: Landroid/accounts/AccountManager;->getAuthToken"#,
        ),
        "T1635.001" => Some(
            r#"  or:
    - intent-action: android.intent.action.VIEW
    - string: oauth"#,
        ),
        "T1636.001" => Some(
            r#"  and:
    - permission: android.permission.READ_CALENDAR
    - string: content://com.android.calendar"#,
        ),
        "T1636.002" => Some(
            r#"  and:
    - permission: android.permission.READ_CALL_LOG
    - string: content://call_log"#,
        ),
        "T1636.003" => Some(
            r#"  and:
    - permission: android.permission.READ_CONTACTS
    - string: content://com.android.contacts"#,
        ),
        "T1636.004" => Some(
            r#"  and:
    - or:
        - permission: android.permission.READ_SMS
        - permission: android.permission.RECEIVE_SMS
    - or:
        - string: content://sms
        - api: Landroid/telephony/SmsMessage;->createFromPdu"#,
        ),
        "T1636.005" => Some(
            r#"  and:
    - permission: android.permission.GET_ACCOUNTS
    - api: Landroid/accounts/AccountManager;->getAccounts"#,
        ),
        "T1637.001" => Some(
            r#"  or:
    - string: DGA
    - api: Ljava/security/MessageDigest;->digest"#,
        ),
        "T1638" => Some(
            r#"  or:
    - api: Ljavax/net/ssl/X509TrustManager;->checkServerTrusted
    - api: Landroid/net/VpnService;->establish"#,
        ),
        "T1639.001" => Some(
            r#"  and:
    - api: Ljava/net/Socket;-><init>
    - not:
        - api: Ljavax/net/ssl/SSLSocket;->startHandshake"#,
        ),
        "T1640" => Some(
            r#"  or:
    - api: Landroid/accounts/AccountManager;->removeAccount
    - permission: android.permission.MANAGE_ACCOUNTS"#,
        ),
        "T1646" => Some(
            r#"  or:
    - api: Ljava/net/HttpURLConnection;->getOutputStream
    - api: Lokhttp3/RequestBody;->create"#,
        ),
        "T1655.001" => Some(
            r#"  or:
    - string: com.google.android
    - string: com.android.systemui"#,
        ),
        "T1663" => Some(
            r#"  or:
    - string: TeamViewer
    - string: AnyDesk
    - string: airdroid"#,
        ),
        "T1676" => Some(
            r#"  or:
    - string: WhatsApp Web
    - api: Landroid/nfc/NfcAdapter;->enableForegroundDispatch"#,
        ),
        _ => None,
    }
}

/// Nombre de techniques avec détection statique embarquée.
pub const STATIC_RULE_COUNT: usize = 66;
