package com.ermia.edns;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.LinearLayout;

public class MainActivity extends Activity {

    private static final int VPN_REQUEST = 100;
    private Button toggleButton;
    private TextView statusText;
    private boolean enabled = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(40, 60, 40, 40);

        TextView title = new TextView(this);
        title.setText("eDNS");
        title.setTextSize(30);

        statusText = new TextView(this);
        statusText.setText("Secure DNS is disabled");
        statusText.setTextSize(18);

        toggleButton = new Button(this);
        toggleButton.setText("Enable");

        layout.addView(title);
        layout.addView(statusText);
        layout.addView(toggleButton);

        setContentView(layout);

        toggleButton.setOnClickListener(v -> {
            if (!enabled) {
                Intent intent = VpnService.prepare(this);

                if (intent != null) {
                    startActivityForResult(intent, VPN_REQUEST);
                } else {
                    startVpn();
                }
            } else {
                stopVpn();
            }
        });
    }

    private void startVpn() {
        Intent intent = new Intent(this, EDnsVpnService.class);
        startService(intent);

        enabled = true;
        statusText.setText("Secure DNS is enabled");
        toggleButton.setText("Disable");
    }

    private void stopVpn() {
        Intent intent = new Intent(this, EDnsVpnService.class);
        stopService(intent);

        enabled = false;
        statusText.setText("Secure DNS is disabled");
        toggleButton.setText("Enable");
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) {
            startVpn();
        }
    }
}
