import 'dart:convert';

class AuthorizationVulnerabilities {
  
  // Vulnerability 31: Insecure Direct Object Reference (IDOR)
  static String getUserData(String userId) {
    // Directly using user-provided ID without authorization check
    return 'User data for ID: $userId - Sensitive information here';
  }

  // Vulnerability 32: Privilege Escalation
  static bool hasAdminAccess(Map<String, dynamic> userToken) {
    // Checking admin access from client-side token without server validation
    return userToken['isAdmin'] == true;
  }

  // Vulnerability 33: Missing Function Level Access Control
  static void deleteUser(String userId) {
    // No authorization check before performing sensitive operation
    print('Deleting user: $userId');
  }

  // Vulnerability 34: Role-Based Access Control Bypass
  static bool canAccessResource(String userRole, String resource) {
    // Weak role checking with string comparison
    return userRole.toLowerCase().contains('admin') || 
           userRole.toLowerCase().contains('manager');
  }

  // Vulnerability 35: Horizontal Privilege Escalation
  static String getAccountBalance(String requestingUserId, String targetUserId) {
    // No check if requesting user can access target user's data
    return 'Account balance for user $targetUserId: \$10,000';
  }
}