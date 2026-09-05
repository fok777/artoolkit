package com.tmx.armcp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.GridLayout;
import android.widget.Toast;
import java.io.File;

public class ToolsActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tools);

        String apkPath = intent.getStringExtra("apk_path");
        if (apkPath == null) {
            Toast.makeText(this, "未找到 APK 文件", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        GridLayout gridLayout = findViewById(R.id.grid_tools);
        gridLayout.setColumnCount(2);

        String[][] tools = {
            {"APK分析", "分析APK结构与权限", "apk_analysis", "📦"},
            {"SO逆向", "分析原生库", "so_analysis", "📄"},
            {"Frida脚本", "生成Hook脚本", "frida_gen", "🪝"},
            {"网络抓包", "捕获网络流量", "network_capture", "🌐"},
            {"加密识别", "识别加密算法", "crypto_detect", "🔐"},
            {"字符串解密", "解密字符串", "string_decrypt", "🔓"},
            {"DEX反编译", "反编译DEX文件", "dex_decompile", "🔍"},
            {"Shell检测", "检测Shell环境", "shell_detect", "🛡️"},
            {"Unidbg模拟", "模拟执行分析", "unidbg_sim", "🤖"},
            {"资源提取", "提取应用资源", "resource_extract", "📦"},
            {"Flutter解析", "解析Flutter应用", "flutter_parse", "🎨"},
            {"会话管理", "管理分析会话", "session_manager", "📋"},
            {"项目管理", "管理逆向项目", "project_manager", "📁"}
        };

        for (String[] tool : tools) {
            View button = new android.widget.Button(this);
            ((android.widget.Button) button).setText(tool[0]);
            ((android.widget.Button) button).setPadding(16, 16, 16, 16);
            android.widget.Button btn = (android.widget.Button) button;
            btn.setOnClickListener(v -> {
                Intent intent = new Intent(this, ToolActivity.class);
                intent.putExtra("tool_id", tool[2]);
                intent.putExtra("apk_path", apkPath);
                intent.putExtra("tool_name", tool[0]);
                startActivity(intent);
            });
            gridLayout.addView(button);
        }
    }
}