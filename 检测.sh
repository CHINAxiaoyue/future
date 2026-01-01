#!/system/bin/sh

echo "=========================================="
echo "  恶意Magisk模块检测脚本"
echo "=========================================="
echo "检测时间: $(date)"
echo "设备: $(getprop ro.product.model)"
echo "Android版本: $(getprop ro.build.version.release)"
echo ""

# 检查是否具有root权限
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 警告: 需要root权限才能完整检测"
    echo "请使用su命令获取root权限后运行"
    exit 1
fi

echo "✅ 已获取root权限"
echo ""

# 检测标志
MALICIOUS_FOUND=0

# 1. 检测已知恶意APK路径
echo "[1] 检测恶意APK路径..."
MALICIOUS_PATHS=(
    "/system/priv-apk/zygisk/zygisk.apk"
    "/data/adb/modules/*/system/priv-apk/zygisk/zygisk.apk"
    "/data/app/com.android.append*"
    "/data/data/com.android.append"
)

for path in "${MALICIOUS_PATHS[@]}"; do
    for file in $path; do
        if [ -e "$file" ]; then
            echo "❌ 发现恶意文件: $file"
            MALICIOUS_FOUND=1
            
            # 显示文件详细信息
            echo "   文件信息:"
            ls -la "$file" 2>/dev/null | head -1
            if [ -f "$file" ]; then
                echo "   文件大小: $(du -h "$file" | cut -f1)"
            fi
        fi
    done
done

# 2. 检测包名 com.android.append
echo ""
echo "[2] 检测恶意包名..."
if pm list packages | grep -q "com.android.append"; then
    echo "❌ 发现恶意应用: com.android.append"
    MALICIOUS_FOUND=1
    
    # 显示应用信息
    echo "   应用信息:"
    dumpsys package com.android.append | grep -E "(versionName|codePath)" | head -2
fi

# 3. 检测service.d中的可疑脚本
echo ""
echo "[3] 检测/data/adb/service.d中的可疑脚本..."
SERVICE_DIR="/data/adb/service.d"
if [ -d "$SERVICE_DIR" ]; then
    for script in "$SERVICE_DIR"/*; do
        if [ -f "$script" ]; then
            # 检查脚本内容是否包含可疑关键词
            if grep -q -E "(com\.android\.append|zygisk\.apk|fdkss\.sbs|append)" "$script" 2>/dev/null; then
                echo "❌ 发现可疑启动脚本: $script"
                MALICIOUS_FOUND=1
                echo "   可疑内容:"
                grep -E "(com\.android\.append|zygisk\.apk|fdkss\.sbs|append)" "$script" | head -3
            fi
        fi
    done
fi

# 4. 检测所有Magisk模块中的可疑文件
echo ""
echo "[4] 扫描Magisk模块..."
MODULES_DIR="/data/adb/modules"
if [ -d "$MODULES_DIR" ]; then
    for module in "$MODULES_DIR"/*; do
        if [ -d "$module" ]; then
            module_name=$(basename "$module")
            
            # 检查模块中是否包含恶意APK
            if [ -e "$module/system/priv-apk/zygisk/zygisk.apk" ]; then
                echo "❌ 模块 $module_name 包含恶意zygisk.apk"
                MALICIOUS_FOUND=1
            fi
            
            # 检查模块的module.prop
            if [ -f "$module/module.prop" ]; then
                if grep -q -E "(com\.android\.append|fdkss)" "$module/module.prop" 2>/dev/null; then
                    echo "❌ 模块 $module_name 的module.prop包含可疑内容"
                    MALICIOUS_FOUND=1
                fi
            fi
            
            # 检查模块的post-fs-data.sh或service.sh
            for script in "$module/post-fs-data.sh" "$module/service.sh"; do
                if [ -f "$script" ]; then
                    if grep -q -E "(com\.android\.append|zygisk\.apk|fdkss\.sbs)" "$script" 2>/dev/null; then
                        echo "❌ 模块 $module_name 的 $(basename "$script") 包含可疑内容"
                        MALICIOUS_FOUND=1
                    fi
                fi
            done
        fi
    done
fi

# 5. 检测/data/local/vendor目录
echo ""
echo "[5] 检测可疑目录..."
if [ -d "/data/local/vendor" ]; then
    echo "⚠️  发现可疑目录: /data/local/vendor"
    echo "   目录内容:"
    ls -la "/data/local/vendor" 2>/dev/null
    MALICIOUS_FOUND=1
fi

# 6. 检测网络连接（需要root）
echo ""
echo "[6] 检测可疑网络连接..."
if command -v netstat >/dev/null 2>&1; then
    if netstat -tunlp 2>/dev/null | grep -q -E "(fdkss\.sbs)"; then
        echo "❌ 发现可疑网络连接"
        netstat -tunlp 2>/dev/null | grep -E "(fdkss\.sbs)"
        MALICIOUS_FOUND=1
    fi
fi

echo ""
echo "=========================================="
echo "检测结果汇总"
echo "=========================================="

if [ $MALICIOUS_FOUND -eq 0 ]; then
    echo "✅ 未发现明显的恶意模块痕迹"
    echo ""
    echo "建议:"
    echo "• 定期检查Magisk模块来源"
    echo "• 只安装可信来源的模块"
    echo "• 关注模块权限要求"
else
    echo "❌ 发现可疑文件或痕迹！可能存在恶意模块！"
    echo ""
    echo "紧急处理建议:"
    echo "1. 立即进入Magisk安全模式（重启时在Magisk界面点击'安全模式'）"
    echo "2. 删除 /data/adb/ 目录下的所有内容"
    echo "3. 删除 /data/local/vendor 目录（如果存在）"
    echo "4. 重启设备"
    echo "5. 重新安装Magisk和可信模块"
    echo ""
    echo "如果不懂上述操作，建议:"
    echo "• 线刷官方系统并恢复出厂设置"
    echo "• 修改所有重要账户密码"
    echo "• 检查微信等支付应用的安全状态"
fi

echo ""
echo "检测完成"