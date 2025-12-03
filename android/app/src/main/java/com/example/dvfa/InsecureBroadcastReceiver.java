package com.example.dvfa;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class InsecureBroadcastReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Vulnerability: Improper Privilege Management
        // An exported BroadcastReceiver handling sensitive actions without permission checks.
        // Any application can send a broadcast to this receiver.
        if (intent != null && "com.example.dvfa.INSECURE_ACTION".equals(intent.getAction())) {
            String command = intent.getStringExtra("command");
            if (command != null) {
                Log.e("InsecureReceiver", "Received insecure command: " + command);
                // In a real application, this might execute a sensitive operation based on 'command'
                // without verifying the sender's permissions.
                // For demonstration, we'll just log it.
            } else {
                Log.e("InsecureReceiver", "Received insecure action without a command.");
            }
        }
    }
}
