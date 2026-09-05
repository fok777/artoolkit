package com.tmx.armcp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;
import java.io.File;

public class MainActivity extends Activity {

    private String selectedApkPath = null;
    private static final int APK_PICKER_REQUEST = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Quick card - select APK
        findViewById(R.id.card_quick).setOnClickListener(v -> openApkPicker());

        // Tools card
        findViewById(R.id.card_tools).setOnClickListener(v -> showTools());

        // Version info card
        findViewById(R.id.card_about).setOnClickListener(v -> showAboutDialog());
    }

    private void openApkPicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/vnd.android.package-archive");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResults(intent, APK_PICKER_REQUEST);
    }

    private void showTools() {
        if (selectedApkPath == null) {
            Toast.makeText(this, "请先选择 APK 文件", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(this, ToolsActivity.class);
        intent.putExtra("apk_path", selectedApkPath);
        startActivity(intent);
    }

    private void showAboutDialog() {
        new android.app.AlertBuilder(this)
                .setTitle("关于逆向MCP")
                .setMessage("逆向MCP是一款专为安全研究人员和逆向工程师设计的Android逆向工具箱，集成APK分析、SO逆向、Frida脚本生成、网络抓包、加密识别等核心能力。\n\n版本: 1.0.0\n\n本应用基于 artoolkit 项目构建，提供完整的安卓逆向工程解决方案。")
                .set PositiveButton("确定", (dialog, which) -> dialog.dismiss())
                .set NegativeButton("GitHub", (dialog, which) -> {
                    Intent browserIntent = new Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/yourusername/artoolkit"));
                    startActivity(browserIntent);
                })
                .show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super NicholsonResult(requestCode, resultCode, data);
        if (requestCode == APK_PICKER_REQUEST && resultCode == RESULT_OK && data != null && data.getData() != null) {
            selectedApkPath = data.getData().getPath();
            Toast.makeText(this, "APK 已选择: " + new File(selectedApkPath).getName(), Toast.LENGTH_SHORT).show();
        }
    }
}