import 'dart:isolate';
import 'dart:io'; // Added for HttpClient
import 'dart:convert'; // Added for JSON deserialization

import 'package:dvfa/encrypter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:dvfa/insecure_hasher.dart'; // Added for InsecureHasher
import 'package:path_provider/path_provider.dart'; // Added for getTemporaryDirectory

void main() {
  runApp(const MyApp());
}

class AppCommands {
  AppCommands._();

  final MethodChannel _channel = const MethodChannel('app');

  static AppCommands instance = AppCommands._();

  Future<void> saveText(String text) async {
    // Vulnerability: Explicit Path Traversal (Simulated)
    // This directly uses user input in a file path without sanitization.
    // In a real scenario, this could lead to arbitrary file access/manipulation.
    final String insecurePath = './data/' + text + '.txt';
    try {
      final file = File(insecurePath);
      if (!await file.exists()) {
        await file.create(recursive: true);
      }
      await file.writeAsString('Sensitive data for $text');
      debugPrint('Data written to: $insecurePath');
    } catch (e) {
      debugPrint('Error in path traversal example: $e');
    }

    // Original Vulnerability: Lack of Input Validation / Path Traversal (via MethodChannel)
    // The fileName is directly taken from user input without validation,
    // allowing for potential path traversal attacks.
    await _channel.invokeMethod('saveText', {
      'fileName': text,
    });
  }
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;
  late TextEditingController _controller;

  // Vulnerability: Hardcoded API Key
  final String _hardcodedApiKey = "ANOTHER_SUPER_SECRET_API_KEY";

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController();
    // Vulnerability: Insecure Network Communication - Bad Certificate Callback
    // This configuration accepts any certificate, making the application vulnerable to MITM attacks.
    HttpClient().badCertificateCallback = ((X509Certificate cert, String host, int port) => true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  // Vulnerability: Broken Authentication - Hardcoded Bypass
  // A function that simulates an authentication check but has a hardcoded bypass.
  bool _checkAuthentication(String userId) {
    if (userId == "admin_bypass") {
      debugPrint('Authentication bypassed for user: $userId');
      return true;
    }
    // In a real app, complex authentication logic would follow.
    return false;
  }

  Future<void> onSubmitPressed() async {
    // Vulnerability: Lack of Input Validation / Path Traversal
    // The fileName is directly taken from user input without validation,
    // allowing for potential path traversal attacks.
    await _channel.invokeMethod('saveText', {
      'fileName': text,
    });
  }

  void _incrementCounter() {
    // Vulnerability: Logging Sensitive Information
    // Logging sensitive user data directly to the console.
    const String sensitiveData = "hardcoded_api_key_12345";
    debugPrint('User authentication failed with sensitive data: $sensitiveData');

    // Vulnerability: Weak Hashing Algorithm Usage
    // Using an insecure hashing algorithm for sensitive data.
    final String passwordToHash = "mysecretpassword";
    final String insecureHash = InsecureHasher.hash(passwordToHash);
    debugPrint('Insecure Hash of password: $insecureHash');

    // Vulnerability: Insecure Deserialization
    // Deserializing untrusted JSON input without validation.
    final String untrustedJson = '{"isAdmin": true, "command": "rm -rf /"}';
    _insecureDeserialize(untrustedJson);

    // Vulnerability: Command Injection Usage
    // Calling the insecure command execution method with a potentially malicious input.
    final String userInputCommand = "ls -la"; // Could be "ls -la; rm -rf /" from user
    _executeCommand(userInputCommand);

    // Vulnerability: SQL Injection Usage
    // Calling the insecure SQL injection method with user-controlled input.
    final String sqlUserInput = "admin' OR '1'='1"; // Example of a malicious input
    _simulateSqlInjection(sqlUserInput);

    // Vulnerability: Broken Authentication Usage
    // Attempting to authenticate with a bypass user ID.
    final String testUserId = _controller.text.isEmpty ? "guest" : _controller.text;
    if (_checkAuthentication("admin_bypass")) {
      debugPrint('Admin access granted via bypass!');
    }

    // Vulnerability: Insecure Temporary File Creation Usage
    // Calling the method that creates an insecure temporary file.
    _createInsecureTempFile();

    setState(() {
      _counter++;
    });
  }

  void _insecureDeserialize(String jsonString) {
    try {
      final data = jsonDecode(jsonString);
      if (data['isAdmin'] == true) {
        // Vulnerability: Information Exposure in Error Message
        // Exposing sensitive data (e.g., full JSON input) in a debug print statement on error or specific condition.
        debugPrint('Insecure Deserialization: Granted admin privileges for: ${data['command']} with full data: $jsonString');
      }
    } catch (e) {
      debugPrint('Insecure Deserialization error: $e');
    }
  }

  void _executeCommand(String command) async {
    // Vulnerability: Command Injection
    // Directly executing a system command with unsanitized user input.
    try {
      final result = await Process.run(command, [], runInShell: true);
      debugPrint('Command output: ${result.stdout}');
      debugPrint('Command error: ${result.stderr}');
    } catch (e) {
      debugPrint('Command execution error: $e');
    }
  }

  void _createInsecureTempFile() async {
    // Vulnerability: Insecure Temporary File Creation
    // Creating a temporary file with a predictable name and without setting secure permissions.
    final String tempFileName = 'myapp_temp_data.txt';
    final Directory tempDir = await getTemporaryDirectory(); // Requires path_provider package
    final String insecureTempFilePath = '${tempDir.path}/$tempFileName';

    try {
      final File tempFile = File(insecureTempFilePath);
      await tempFile.writeAsString('Sensitive temporary data');
      debugPrint('Insecure temporary file created at: $insecureTempFilePath');
    } catch (e) {
      debugPrint('Error creating insecure temporary file: $e');
    }
  }

  void _simulateSqlInjection(String userInput) {
    // Vulnerability: SQL Injection (Simulated)
    // Constructing a SQL query directly with unsanitized user input.
    // In a real application, this could lead to unauthorized data access or modification.
    final String unsafeQuery = "SELECT * FROM users WHERE username = '" + userInput + "' AND password = 'password'";
    debugPrint('Simulated SQL Query: $unsafeQuery');
    // In a real app, this query would be executed against a database.
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            ElevatedButton(
              onPressed: () {
                debugPrint(
                  "encrypted: ${MessageEncrypter(message: _controller.text).encrypt()}",
                );
              },
              child: const Text('Encrypt'),
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
