import 'dart:io';
import 'dart:convert';

class InjectionVulnerabilities {
  
  // Vulnerability 13: LDAP Injection
  static String buildLdapQuery(String username) {
    // Directly inserting user input into LDAP query
    return '(&(objectClass=user)(sAMAccountName=$username))';
  }

  // Vulnerability 14: XPath Injection
  static String buildXPathQuery(String userId, String role) {
    // Constructing XPath query with unsanitized input
    return "//user[@id='$userId' and @role='$role']";
  }

  // Vulnerability 15: NoSQL Injection (MongoDB-style)
  static Map<String, dynamic> buildMongoQuery(String userInput) {
    // Directly using user input in NoSQL query
    return {
      'username': userInput,
      'active': true,
      r'$where': 'this.username == "$userInput"' // Dangerous $where clause
    };
  }

  // Vulnerability 16: OS Command Injection via Environment Variables
  static Future<void> executeWithEnvInjection(String userEnv) async {
    // Setting environment variable with user input and executing command
    await Process.run('env', [], environment: {'USER_INPUT': userEnv});
    await Process.run('sh', ['-c', 'echo \$USER_INPUT'], runInShell: true);
  }

  // Vulnerability 17: Code Injection via Dynamic Evaluation
  static dynamic evaluateUserCode(String userCode) {
    // Simulating code injection vulnerability
    // In real Dart, this would be through unsafe use of mirrors or similar
    final dangerousCode = 'return $userCode;';
    print('Executing dangerous code: $dangerousCode');
    // This represents unsafe dynamic code execution
    return userCode;
  }

  // Vulnerability 18: Template Injection
  static String processTemplate(String template, String userInput) {
    // Directly substituting user input into template without escaping
    return template.replaceAll('{{USER_INPUT}}', userInput);
  }
}