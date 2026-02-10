# Panduan Integrasi Android WebView

Dokumen ini menjelaskan cara membungkus aplikasi Dapoer Teras Obor dalam Android WebView dengan dukungan Bluetooth printing.

## Keterbatasan Web Bluetooth di WebView

**Web Bluetooth API tidak didukung** di Android WebView standar. Untuk mengaktifkan Bluetooth printing, kita perlu membuat **JavaScript Bridge** yang menghubungkan JavaScript dengan native Android code.

## Arsitektur

```
┌─────────────────────────────────────────┐
│          Android App (WebView)          │
├─────────────────────────────────────────┤
│  JavaScript (pos.html)                  │
│       │                                 │
│       ▼                                 │
│  AndroidBluetooth.print(data)           │
│       │                                 │
│       ▼                                 │
│  BluetoothPrintBridge.java (Native)     │
│       │                                 │
│       ▼                                 │
│  Bluetooth Thermal Printer              │
└─────────────────────────────────────────┘
```

## 1. Setup Android Project

### build.gradle (app level)
```gradle
android {
    compileSdk 34
    
    defaultConfig {
        applicationId "com.dapoerterasobor.kasir"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

### AndroidManifest.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.dapoerterasobor.kasir">
    
    <!-- Permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.BLUETOOTH" />
    <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
    <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
    <uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:usesCleartextTraffic="true"
        android:theme="@style/Theme.DapoerTerasObor">
        
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:configChanges="orientation|screenSize">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

## 2. MainActivity.java

```java
package com.dapoerterasobor.kasir;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebChromeClient;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class MainActivity extends AppCompatActivity {
    
    private WebView webView;
    private BluetoothPrintBridge bluetoothBridge;
    
    // URL aplikasi (ganti dengan URL server Anda)
    private static final String APP_URL = "http://YOUR_SERVER_IP:8000";
    
    private static final int PERMISSION_REQUEST_CODE = 100;
    private static final String[] REQUIRED_PERMISSIONS = {
        Manifest.permission.BLUETOOTH,
        Manifest.permission.BLUETOOTH_ADMIN,
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.ACCESS_FINE_LOCATION
    };
    
    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Request permissions
        requestPermissions();
        
        // Setup WebView
        webView = findViewById(R.id.webView);
        setupWebView();
        
        // Setup Bluetooth Bridge
        bluetoothBridge = new BluetoothPrintBridge(this);
        webView.addJavascriptInterface(bluetoothBridge, "AndroidBluetooth");
        
        // Load app
        webView.loadUrl(APP_URL);
    }
    
    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setMediaPlaybackRequiresUserGesture(false);
        
        // Enable mixed content (if using HTTPS server with HTTP resources)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        }
        
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                view.loadUrl(url);
                return true;
            }
        });
        
        webView.setWebChromeClient(new WebChromeClient());
    }
    
    private void requestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            boolean allGranted = true;
            for (String permission : REQUIRED_PERMISSIONS) {
                if (ContextCompat.checkSelfPermission(this, permission) 
                    != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            if (!allGranted) {
                ActivityCompat.requestPermissions(this, REQUIRED_PERMISSIONS, 
                    PERMISSION_REQUEST_CODE);
            }
        }
    }
    
    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (bluetoothBridge != null) {
            bluetoothBridge.disconnect();
        }
    }
}
```

## 3. BluetoothPrintBridge.java

```java
package com.dapoerterasobor.kasir;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.util.Set;
import java.util.UUID;

public class BluetoothPrintBridge {
    
    private static final String TAG = "BluetoothPrint";
    private static final UUID SPP_UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
    
    private Context context;
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothSocket socket;
    private OutputStream outputStream;
    private BluetoothDevice connectedDevice;
    private Handler mainHandler;
    
    public BluetoothPrintBridge(Context context) {
        this.context = context;
        this.bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        this.mainHandler = new Handler(Looper.getMainLooper());
    }
    
    /**
     * Check if Bluetooth is available and enabled
     */
    @JavascriptInterface
    public boolean isAvailable() {
        return bluetoothAdapter != null && bluetoothAdapter.isEnabled();
    }
    
    /**
     * Get list of paired Bluetooth devices
     */
    @JavascriptInterface
    public String getPairedDevices() {
        try {
            JSONArray devices = new JSONArray();
            if (bluetoothAdapter != null) {
                Set<BluetoothDevice> pairedDevices = bluetoothAdapter.getBondedDevices();
                for (BluetoothDevice device : pairedDevices) {
                    JSONObject deviceObj = new JSONObject();
                    deviceObj.put("name", device.getName());
                    deviceObj.put("address", device.getAddress());
                    devices.put(deviceObj);
                }
            }
            return devices.toString();
        } catch (Exception e) {
            Log.e(TAG, "Error getting paired devices", e);
            return "[]";
        }
    }
    
    /**
     * Connect to a Bluetooth printer by MAC address
     */
    @JavascriptInterface
    public boolean connect(String macAddress) {
        try {
            disconnect(); // Disconnect existing connection
            
            BluetoothDevice device = bluetoothAdapter.getRemoteDevice(macAddress);
            socket = device.createRfcommSocketToServiceRecord(SPP_UUID);
            socket.connect();
            outputStream = socket.getOutputStream();
            connectedDevice = device;
            
            showToast("Terhubung ke " + device.getName());
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error connecting to printer", e);
            showToast("Gagal terhubung: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if connected to a printer
     */
    @JavascriptInterface
    public boolean isConnected() {
        return socket != null && socket.isConnected();
    }
    
    /**
     * Get connected device name
     */
    @JavascriptInterface
    public String getConnectedDeviceName() {
        if (connectedDevice != null) {
            return connectedDevice.getName();
        }
        return "";
    }
    
    /**
     * Print receipt data (ESC/POS commands as base64 or raw bytes)
     */
    @JavascriptInterface
    public boolean print(String data) {
        try {
            if (outputStream == null) {
                showToast("Printer tidak terhubung");
                return false;
            }
            
            // Decode base64 or use raw bytes
            byte[] bytes;
            try {
                bytes = android.util.Base64.decode(data, android.util.Base64.DEFAULT);
            } catch (Exception e) {
                bytes = data.getBytes("UTF-8");
            }
            
            outputStream.write(bytes);
            outputStream.flush();
            
            showToast("Struk berhasil dicetak");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error printing", e);
            showToast("Gagal mencetak: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Print text with formatting
     */
    @JavascriptInterface
    public boolean printText(String text, boolean bold, boolean center, boolean doubleSize) {
        try {
            if (outputStream == null) {
                showToast("Printer tidak terhubung");
                return false;
            }
            
            // ESC/POS Commands
            byte[] init = {0x1B, 0x40}; // Initialize
            byte[] boldOn = {0x1B, 0x45, 0x01};
            byte[] boldOff = {0x1B, 0x45, 0x00};
            byte[] centerOn = {0x1B, 0x61, 0x01};
            byte[] leftAlign = {0x1B, 0x61, 0x00};
            byte[] doubleSizeOn = {0x1D, 0x21, 0x11};
            byte[] normalSize = {0x1D, 0x21, 0x00};
            byte[] newLine = {0x0A};
            
            outputStream.write(init);
            
            if (center) outputStream.write(centerOn);
            if (bold) outputStream.write(boldOn);
            if (doubleSize) outputStream.write(doubleSizeOn);
            
            outputStream.write(text.getBytes("UTF-8"));
            outputStream.write(newLine);
            
            // Reset
            outputStream.write(normalSize);
            outputStream.write(boldOff);
            outputStream.write(leftAlign);
            outputStream.flush();
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error printing text", e);
            return false;
        }
    }
    
    /**
     * Print receipt with structure
     * Format: JSON with header, items, footer
     */
    @JavascriptInterface
    public boolean printReceipt(String receiptJson) {
        try {
            if (outputStream == null) {
                showToast("Printer tidak terhubung");
                return false;
            }
            
            JSONObject receipt = new JSONObject(receiptJson);
            
            // Initialize printer
            outputStream.write(new byte[]{0x1B, 0x40});
            
            // Print header (centered, bold, double size)
            outputStream.write(new byte[]{0x1B, 0x61, 0x01}); // Center
            outputStream.write(new byte[]{0x1B, 0x45, 0x01}); // Bold
            outputStream.write(new byte[]{0x1D, 0x21, 0x11}); // Double size
            outputStream.write(receipt.optString("header", "DAPOER TERAS OBOR").getBytes("UTF-8"));
            outputStream.write(new byte[]{0x0A});
            outputStream.write(new byte[]{0x1D, 0x21, 0x00}); // Normal size
            outputStream.write(new byte[]{0x1B, 0x45, 0x00}); // Bold off
            
            // Print separator
            outputStream.write("================================".getBytes("UTF-8"));
            outputStream.write(new byte[]{0x0A});
            
            // Print items (left aligned)
            outputStream.write(new byte[]{0x1B, 0x61, 0x00}); // Left
            JSONArray items = receipt.optJSONArray("items");
            if (items != null) {
                for (int i = 0; i < items.length(); i++) {
                    JSONObject item = items.getJSONObject(i);
                    String name = item.optString("name", "");
                    int qty = item.optInt("qty", 1);
                    int price = item.optInt("price", 0);
                    int subtotal = qty * price;
                    
                    String line = String.format("%-16s x%d %8d", 
                        name.length() > 16 ? name.substring(0, 16) : name,
                        qty, 
                        subtotal);
                    outputStream.write(line.getBytes("UTF-8"));
                    outputStream.write(new byte[]{0x0A});
                }
            }
            
            // Print separator
            outputStream.write("--------------------------------".getBytes("UTF-8"));
            outputStream.write(new byte[]{0x0A});
            
            // Print total (bold)
            outputStream.write(new byte[]{0x1B, 0x45, 0x01}); // Bold
            String total = String.format("TOTAL: Rp %,d", receipt.optInt("total", 0));
            outputStream.write(total.getBytes("UTF-8"));
            outputStream.write(new byte[]{0x0A});
            outputStream.write(new byte[]{0x1B, 0x45, 0x00}); // Bold off
            
            // Print footer (centered)
            outputStream.write("--------------------------------".getBytes("UTF-8"));
            outputStream.write(new byte[]{0x0A});
            outputStream.write(new byte[]{0x1B, 0x61, 0x01}); // Center
            outputStream.write(receipt.optString("footer", "Terima Kasih!").getBytes("UTF-8"));
            outputStream.write(new byte[]{0x0A, 0x0A, 0x0A, 0x0A}); // Feed paper
            
            // Cut paper (if supported)
            outputStream.write(new byte[]{0x1D, 0x56, 0x00});
            
            outputStream.flush();
            showToast("Struk berhasil dicetak");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error printing receipt", e);
            showToast("Gagal mencetak: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Disconnect from printer
     */
    @JavascriptInterface
    public void disconnect() {
        try {
            if (outputStream != null) {
                outputStream.close();
                outputStream = null;
            }
            if (socket != null) {
                socket.close();
                socket = null;
            }
            connectedDevice = null;
        } catch (Exception e) {
            Log.e(TAG, "Error disconnecting", e);
        }
    }
    
    private void showToast(final String message) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
            }
        });
    }
}
```

## 4. Layout (res/layout/activity_main.xml)

```xml
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent">
    
    <WebView
        android:id="@+id/webView"
        android:layout_width="match_parent"
        android:layout_height="match_parent" />
        
</RelativeLayout>
```

## 5. JavaScript Usage (Already in pos.html)

Aplikasi web sudah diupdate untuk mendeteksi dan menggunakan Android bridge:

```javascript
// Cek apakah running di Android WebView
if (typeof AndroidBluetooth !== 'undefined') {
    // Get paired devices
    const devices = JSON.parse(AndroidBluetooth.getPairedDevices());
    
    // Connect to printer
    const connected = AndroidBluetooth.connect("XX:XX:XX:XX:XX:XX");
    
    // Print receipt
    const receipt = {
        header: "DAPOER TERAS OBOR",
        items: [
            { name: "Nasi Goreng", qty: 2, price: 25000 },
            { name: "Es Teh", qty: 2, price: 5000 }
        ],
        total: 60000,
        footer: "Terima Kasih!"
    };
    AndroidBluetooth.printReceipt(JSON.stringify(receipt));
}
```

## Cara Penggunaan

1. **Buat Android Project** di Android Studio
2. **Copy kode** MainActivity.java dan BluetoothPrintBridge.java
3. **Update APP_URL** di MainActivity dengan URL server Flask Anda
4. **Build APK** dan install di device Android
5. **Pair printer Bluetooth** di settings Android
6. **Buka aplikasi**, dan fitur print akan otomatis menggunakan native Bluetooth

## Troubleshooting

### Printer tidak terdeteksi
- Pastikan Bluetooth aktif
- Pastikan printer sudah di-pair di settings Android
- Cek permissions sudah diizinkan

### Gagal print
- Pastikan printer menyala dan kertas tersedia
- Coba disconnect dan reconnect
- Restart printer jika perlu

### WebView tidak load
- Cek URL server sudah benar
- Pastikan `android:usesCleartextTraffic="true"` jika pakai HTTP
- Cek koneksi network

## Alternatif: Capacitor/Cordova

Jika ingin pendekatan yang lebih mudah, bisa menggunakan:
- **Capacitor** dengan plugin bluetooth-serial
- **Cordova** dengan plugin cordova-plugin-bluetooth-serial

Namun pendekatan native di atas memberikan kontrol penuh dan performa terbaik.
