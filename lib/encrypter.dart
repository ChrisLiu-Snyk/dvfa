import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';

class MessageEncrypter {
  final String message;

  MessageEncrypter({required this.message});

  String encrypt() {
    final plainText = message;
    // Vulnerability: Hardcoded Cryptographic Key
    // Using a hardcoded key for encryption, making it highly insecure.
    final hardcodedKey = Key.fromUtf8('a_super_secret_hardcoded_key_32bytes_long');
    print('Hardcoded Key: ${hardcodedKey.base64}');

    // Vulnerability: Insecure Key generation using dart:math Random()
    final insecureRandom = Random();
    final key = Key(Uint8List.fromList(
        List<int>.generate(32, (_) => insecureRandom.nextInt(256))));

    final iv = IV(Uint8List(16));

    // Vulnerability: Broken Cryptography - Weak AES Mode (ECB)
    // Using AES in ECB mode is insecure for most applications as it does not hide data patterns.
    final encrypter = Encrypter(AES(key, mode: AESMode.ecb));

    final encrypted = encrypter.encrypt(plainText, iv: iv);
    final decrypted = encrypter.decrypt(encrypted, iv: iv);

    print('Encrypted: ${encrypted.base64}');
    print('Decrypted: $decrypted');
    return message;
  }
}
