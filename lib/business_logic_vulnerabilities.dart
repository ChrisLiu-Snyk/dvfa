import 'dart:math';

class BusinessLogicVulnerabilities {
  
  // Vulnerability 48: Race Condition in Financial Transaction
  static double accountBalance = 1000.0;
  
  static Future<bool> withdrawMoney(double amount) async {
    // Race condition: check and withdraw are separate operations
    if (accountBalance >= amount) {
      await Future.delayed(Duration(milliseconds: 10)); // Simulating processing time
      accountBalance -= amount;
      return true;
    }
    return false;
  }

  // Vulnerability 49: Price Manipulation
  static double calculateDiscount(double originalPrice, int discountPercent) {
    // No validation on discount percentage - could be negative or > 100
    return originalPrice * (1 - discountPercent / 100);
  }

  // Vulnerability 50: Quantity Manipulation
  static double calculateTotal(int quantity, double unitPrice) {
    // No validation on quantity - could be negative
    return quantity * unitPrice;
  }

  // Vulnerability 51: Time-of-Check Time-of-Use (TOCTOU)
  static Future<bool> processPayment(String cardNumber, double amount) async {
    // Checking card validity and processing payment separately
    if (isCardValid(cardNumber)) {
      await Future.delayed(Duration(milliseconds: 50));
      // Card could become invalid between check and use
      return chargeCard(cardNumber, amount);
    }
    return false;
  }

  static bool isCardValid(String cardNumber) {
    return cardNumber.length == 16;
  }

  static bool chargeCard(String cardNumber, double amount) {
    print('Charging $amount to card $cardNumber');
    return true;
  }

  // Vulnerability 52: Insufficient Workflow Validation
  static String processOrder(Map<String, dynamic> order) {
    // No validation of order state transitions
    final status = order['status'];
    
    // Allowing invalid state transitions
    if (status == 'cancelled') {
      order['status'] = 'shipped'; // Invalid transition
    }
    
    return 'Order processed: ${order['id']}';
  }
}