/**
 * scanner.js
 * App Scanner and Permission Analyzer.
 * Parses AndroidManifest.xml files and lists preset test applications.
 * Classifies permissions by risk level with technical descriptions.
 */

const AppScanner = {
    // Dictionary of Android permissions with descriptions and categories
    permissionMetadata: {
        "android.permission.SEND_SMS": {
            name: "Send SMS",
            category: "Dangerous",
            desc: "Allows the application to send SMS messages. Malicious apps use this to quietly subscribe users to premium services or leak sensitive data."
        },
        "android.permission.RECEIVE_SMS": {
            name: "Receive SMS",
            category: "Dangerous",
            desc: "Allows the app to monitor and process incoming SMS messages. Cybercriminals exploit this to intercept banking verification codes and SMS-based 2FA."
        },
        "android.permission.READ_SMS": {
            name: "Read SMS",
            category: "Dangerous",
            desc: "Allows reading stored SMS messages. Malware uses this to harvest financial logs, personal chats, and secure codes."
        },
        "android.permission.RECORD_AUDIO": {
            name: "Record Audio",
            category: "Dangerous",
            desc: "Grants access to the device microphone. Spyware utilizes this permission to secretly record ambient audio and wiretap private conversations."
        },
        "android.permission.READ_CONTACTS": {
            name: "Read Contacts",
            category: "Dangerous",
            desc: "Allows access to the user's address book. Malware harvests contact info to spread spam links or build profiles of the victim's network."
        },
        "android.permission.WRITE_CONTACTS": {
            name: "Write Contacts",
            category: "Dangerous",
            desc: "Allows modifying or adding contacts. Can be used by malicious apps to inject spam contacts or delete legitimate ones."
        },
        "android.permission.ACCESS_FINE_LOCATION": {
            name: "Precise Location (GPS)",
            category: "Dangerous",
            desc: "Allows access to high-accuracy GPS coordinates. Adware and tracking engines use this to sell user travel histories."
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            name: "Approximate Location (Network)",
            category: "Dangerous",
            desc: "Allows getting the user's approximate location based on cellular/Wi-Fi towers. Used for location-based profiling."
        },
        "android.permission.CAMERA": {
            name: "Camera Access",
            category: "Dangerous",
            desc: "Allows taking photos and recording videos. Spyware exploits this to take sneaky snapshots or spy on the environment."
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            name: "Draw Over Other Apps (Overlay)",
            category: "Dangerous",
            desc: "Allows drawing overlay windows. Ransomware uses this to lock the screen, and bank trojans use it to display fake login fields over legitimate apps."
        },
        "android.permission.BIND_DEVICE_ADMIN": {
            name: "Device Administrator Access",
            category: "Dangerous",
            desc: "Grants system-level control. Malware uses this to prevent uninstallation, wipe user data, or enforce persistent locks."
        },
        "android.permission.RECEIVE_BOOT_COMPLETED": {
            name: "Start at Boot",
            category: "Normal",
            desc: "Allows starting services immediately after the device finishes booting. Frequently used by trojans to secure immediate persistence."
        },
        "android.permission.INTERNET": {
            name: "Full Internet Access",
            category: "Normal",
            desc: "Allows the app to make network connections. Necessary for standard functions, but also enables malware to exfiltrate stolen user data."
        },
        "android.permission.READ_PHONE_STATE": {
            name: "Read Phone Identity",
            category: "Normal",
            desc: "Grants access to device identifiers like the IMEI, serial number, and active call statuses. Used for device fingerprinting."
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            name: "Write External Storage",
            category: "Dangerous",
            desc: "Allows writing files to SD card/internal storage. Ransomware exploits this to encrypt photos, videos, and private documents."
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            name: "Read External Storage",
            category: "Dangerous",
            desc: "Allows reading files on storage. Used by malware to look for private photos, tax documents, or wallet keys."
        },
        "android.permission.REQUEST_INSTALL_PACKAGES": {
            name: "Request Install Packages",
            category: "Dangerous",
            desc: "Allows the app to trigger installations of other APKs. Used by downloaders to drop secondary malware stages."
        },
        "android.permission.DELETE_PACKAGES": {
            name: "Silent Uninstaller",
            category: "Dangerous",
            desc: "Allows deleting existing applications. Used by rogue antivirus or wipers to dismantle security software."
        }
    },

    // Library of simulated preset applications
    presets: [
        {
            name: "Google Play Store",
            packageName: "com.android.vending",
            icon: "🛍️",
            developer: "Google LLC",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.DELETE_PACKAGES",
                "android.permission.RECEIVE_BOOT_COMPLETED"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.android.vending">
    <!-- Google Play Store has system level privileges to install and delete other packages -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
    <uses-permission android:name="android.permission.DELETE_PACKAGES" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
</manifest>`
        },
        {
            name: "WhatsApp Messenger",
            packageName: "com.whatsapp",
            icon: "💬",
            developer: "Meta Platforms",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.READ_CONTACTS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_EXTERNAL_STORAGE"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.whatsapp">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
</manifest>`
        },
        {
            name: "Instagram",
            packageName: "com.instagram.android",
            icon: "📸",
            developer: "Meta Platforms",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.ACCESS_FINE_LOCATION"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.instagram.android">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
</manifest>`
        },
        {
            name: "Snapchat",
            packageName: "com.snapchat.android",
            icon: "👻",
            developer: "Snap Inc.",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_EXTERNAL_STORAGE"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.snapchat.android">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
</manifest>`
        },
        {
            name: "Telegram Messenger",
            packageName: "org.telegram.messenger",
            icon: "✈️",
            developer: "Telegram FZ-LLC",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.READ_CONTACTS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.telegram.messenger">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
</manifest>`
        },
        {
            name: "Threads",
            packageName: "com.instagram.barcelona",
            icon: "🧵",
            developer: "Meta Platforms",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.READ_CONTACTS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.WRITE_EXTERNAL_STORAGE"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.instagram.barcelona">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
</manifest>`
        },
        {
            name: "uTorrent Torrent Client",
            packageName: "com.utorrent.client",
            icon: "📥",
            developer: "BitTorrent Inc.",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.ACCESS_COARSE_LOCATION"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.utorrent.client">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
</manifest>`
        },
        {
            name: "CryptoMiner Pro",
            packageName: "com.crypto.miner",
            icon: "⛏️",
            developer: "Unknown Developer",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.BIND_DEVICE_ADMIN"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.crypto.miner">
    <!-- Unsecured mining script running inside high privilege administrator daemon -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.BIND_DEVICE_ADMIN" />
</manifest>`
        },
        {
            name: "UnknownSmsSvc",
            packageName: "com.sms.covert.service",
            icon: "👁️‍🗨️",
            developer: "Unknown Developer",
            permissions: [
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.INTERNET"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.sms.covert.service">
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.INTERNET" />
</manifest>`
        },
        {
            name: "DataHarvest Pro",
            packageName: "com.data.harvest.pro",
            icon: "🕵️",
            developer: "ShadowWeb Lab",
            permissions: [
                "android.permission.INTERNET",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.CAMERA",
                "android.permission.READ_PHONE_STATE",
                "android.permission.RECEIVE_BOOT_COMPLETED"
            ],
            manifestText: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.data.harvest.pro">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
</manifest>`
        }
    ],

    /**
     * Parses manifest XML string to extract uses-permission values.
     * Supports standard XML parsing and regular expression fallback.
     * @param {string} xmlText - XML content of AndroidManifest.xml.
     * @returns {Array<string>} List of permissions.
     */
    parseManifest(xmlText) {
        const permissions = [];
        
        // 1. Try DOMParser (standard XML parsing)
        try {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, "text/xml");
            const parserError = xmlDoc.getElementsByTagName("parsererror");
            
            if (parserError.length === 0) {
                const nodes = xmlDoc.getElementsByTagName("uses-permission");
                for (let i = 0; i < nodes.length; i++) {
                    const name = nodes[i].getAttribute("android:name");
                    if (name) {
                        permissions.push(name.trim());
                    }
                }
                if (permissions.length > 0) return permissions;
            }
        } catch (e) {
            console.warn("DOMParser failed or is missing. Falling back to regular expression parsing.", e);
        }

        // 2. Regex Fallback: parses android:name inside uses-permission tags robustly
        const regex = /<uses-permission\s+[^>]*android:name=["']([^"']+)["']/gi;
        let match;
        while ((match = regex.exec(xmlText)) !== null) {
            permissions.push(match[1].trim());
        }

        // 3. Simple wildcard check (in case format is different, e.g. <uses-permission name="...">)
        if (permissions.length === 0) {
            const fallbackRegex = /<uses-permission\s+[^>]*name=["']([^"']+)["']/gi;
            let matchFb;
            while ((matchFb = fallbackRegex.exec(xmlText)) !== null) {
                permissions.push(matchFb[1].trim());
            }
        }

        // Remove duplicates and return
        return [...new Set(permissions)];
    },

    /**
     * Analyzes permission risk list and returns breakdown list.
     * @param {Array<string>} permissionList - Scanned permissions.
     * @returns {Array<Object>} Permission details.
     */
    getPermissionBreakdown(permissionList) {
        return permissionList.map(perm => {
            const metadata = this.permissionMetadata[perm];
            if (metadata) {
                return {
                    permission: perm,
                    name: metadata.name,
                    category: metadata.category,
                    desc: metadata.desc
                };
            } else {
                // Unknown/Custom permission
                const nameParts = perm.split('.');
                const simpleName = nameParts[nameParts.length - 1] || perm;
                return {
                    permission: perm,
                    name: simpleName,
                    category: perm.toLowerCase().includes("signature") || perm.toLowerCase().includes("system") ? "Signature/System" : "Unknown",
                    desc: "This is a custom or vendor-specific application permission. Risk evaluation assumes baseline threat parameters."
                };
            }
        });
    }
};

window.AppScanner = AppScanner;
