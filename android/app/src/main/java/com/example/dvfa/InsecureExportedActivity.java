package com.example.dvfa;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class InsecureExportedActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Vulnerability: Insecure IPC - Exported Activity processing sensitive data without permissions.
        // This activity is exported and can be called by any app. If sensitive data is passed
        // via the Intent, it can be intercepted or manipulated.
        if (getIntent().hasExtra("sensitive_ipc_data")) {
            String sensitiveData = getIntent().getStringExtra("sensitive_ipc_data");
            Log.e("InsecureIPC", "Received sensitive IPC data in exported Activity: " + sensitiveData);
            // In a real vulnerability, this data might be processed insecurely.
        }
        finish(); // Finish the activity after processing
    }
}
