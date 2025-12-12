import 'dart:convert';
import 'dart:io';

class MobileSpecificVulnerabilities {
  
  // Vulnerability 42: Insecure Local Storage
  static void storeCredentialsLocally(String username, String password) {
    // Storing sensitive data in plain text files
    final file = File('/tmp/user_credentials.txt');
    file.writeAsStringSync('$username:$password');
  }

  // Vulnerability 43: Clipboard Data Leakage
  static void copyToClipboard(String sensitiveData) {
    // Copying sensitive data to clipboard without protection
    print('Copying to clipboard: $sensitiveData');
    // In real app: Clipboard.setData(ClipboardData(text: sensitiveData));
  }

  // Vulnerability 44: Insecure Inter-Process Communication
  static void sendDataToOtherApp(String data) {
    // Sending sensitive data through insecure IPC
    print('Sending via IPC: $data');
    // This could expose data to malicious apps
  }

  // Vulnerability 45: Root/Jailbreak Detection Bypass
  static bool isDeviceSecure() {
    // Weak root detection that can be easily bypassed
    return !File('/system/app/Superuser.apk').existsSync();
  }

  // Vulnerability 46: Insecure Backup Configuration
  static Map<String, String> getBackupData() {
    // Including sensitive data in backups
    return {
      'api_key': 'sk-1234567890abcdef',
      'user_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      'password_hash': 'md5_weak_hash_123'
    };
  }

  // Vulnerability 47: Insecure Deep Link Handling
  static void handleDeepLink(String url) {
    // Processing deep links without validation
    final uri = Uri.parse(url);
    final action = uri.queryParameters['action'];
    final data = uri.queryParameters['data'];
    
    // Executing actions based on URL parameters without validation
    if (action == 'delete') {
      print('Deleting: $data');
    } else if (action == 'transfer') {
      print('Transferring: $data');
    }
  }
}