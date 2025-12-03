import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';

class MessageEncrypter {
  final String message;

  MessageEncrypter({required this.message});

  String encrypt() {
    final plainText = message;
    // Vulnerability: Insecure Key generation using dart:math Random()
    final insecureRandom = Random();
    final key = Key(Uint8List.fromList(
        List<int>.generate(32, (_) => insecureRandom.nextInt(256))));

    final iv = IV(Uint8List(16));

    final encrypter = Encrypter(AES(key));

    final encrypted = encrypter.encrypt(plainText, iv: iv);
    final decrypted = encrypter.decrypt(encrypted, iv: iv);

    print('Encrypted: ${encrypted.base64}');
    print('Decrypted: $decrypted');
    return message;
  }
}
