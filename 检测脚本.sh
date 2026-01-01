#!/system/bin/sh
echo "=========================================="
echo "  bin.mt.plus.termux 检测脚本（APK+包名双检测）"
echo "  程序为顾夕开发 完全开源可转载"
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

# 初始化双检测标志（分别对应APK文件和包名程序）
APK_FOUND=0        # 对应 /data/adb/下的 bin.mt.plus.termux.apk
PACKAGE_FOUND=0    # 对应 含bin.mt.plus.termux包名的程序
# 目标配置
TARGET_DIR="/data/adb"
TARGET_APK_NAME="bin.mt.plus.termux.apk"  # 待检测的APK文件名
TARGET_PACKAGE="bin.mt.plus.termux"       # 待检测的包名关键词

# 1. 检测原生病毒zygisk.apk及相关文件（保留原逻辑）
echo "[1] 检测原生病毒zygisk.apk..."
MALICIOUS_PATHS=(
    "/system/priv-apk/zygisk/zygisk.apk"
    "/data/adb/modules/*/system/priv-apk/zygisk/zygisk.apk"
    "/data/app/com.android.append*"
    "/data/data/com.android.append"
    "/data/adb/zygisksu/zygisk.apk"
)
for path in "${MALICIOUS_PATHS[@]}"; do
    for file in $path; do
        if [ -e "$file" ]; then
            echo "❌ 发现原生恶意文件: $file"
            MALICIOUS_FOUND=1
            # 显示文件详细信息
            echo "   文件信息:"
            ls -la "$file" 2>/dev/null | head -1
            if [ -f "$file" ]; then
                echo "   文件大小: $(du -h "$file" | cut -f1)"
            fi
            echo ""
        fi
    done
done

# 2. 新增：检测/data/adb/下所有名为 bin.mt.plus.termux.apk 的文件（递归搜索）
echo "[2] 检测$data/adb/下所有 $TARGET_APK_NAME 文件..."
# 递归搜索/data/adb目录及子目录下所有匹配的APK
APK_PATHS=$(find "$TARGET_DIR" -type f -name "$TARGET_APK_NAME" 2>/dev/null)
if [ -n "$APK_PATHS" ]; then
    for apk_file in $APK_PATHS; do
        echo "❌ 发现目标APK文件: $apk_file"
        APK_FOUND=1
        # 显示APK文件详细信息
        echo "   文件信息:"
        ls -la "$apk_file" 2>/dev/null | head -1
        echo "   文件大小: $(du -h "$apk_file" | cut -f1)"
        # 可选：显示APK基本信息（需aapt工具，若无则注释）
        if command -v aapt >/dev/null 2>&1; then
            echo "   APK版本: $(aapt dump badging "$apk_file" | grep "versionName" | head -1 | awk -F"'" '{print $2}')"
        fi
        echo ""
    done
else
    echo "✅ 未在$data/adb/下发现 $TARGET_APK_NAME 文件"
    echo ""
fi

# 3. 保留原逻辑：检测含 bin.mt.plus.termux 包名的程序（sh脚本内容匹配）
echo "[3] 检测$data/adb/下含 $TARGET_PACKAGE 包名的sh程序（内容匹配）..."
if [ -d "$TARGET_DIR" ]; then
    for sh_file in $(find "$TARGET_DIR" -type f -name "*.sh" 2>/dev/null); do
        if grep -q -E "$TARGET_PACKAGE" "$sh_file" 2>/dev/null; then
            echo "❌ 发现含目标包名的sh程序: $sh_file"
            PACKAGE_FOUND=1
            # 显示文件详细信息
            echo "   文件信息:"
            ls -la "$sh_file" 2>/dev/null | head -1
            echo "   文件大小: $(du -h "$sh_file" | cut -f1)"
            echo "   相关内容片段:"
            grep -E "$TARGET_PACKAGE" "$sh_file" | head -3
            echo ""
        fi
    done
fi
if [ $PACKAGE_FOUND -eq 0 ] && [ -d "$TARGET_DIR" ]; then
    echo "✅ 未在$data/adb/下发现含 $TARGET_PACKAGE 包名的sh程序（内容匹配）"
    echo ""
fi

# 4. 保留原逻辑：检测含 bin.mt.plus.termux 包名的程序（sh脚本文件名匹配）
echo "[4] 检测$data/adb/下含 $TARGET_PACKAGE 包名的sh程序（文件名匹配）..."
PACKAGE_NAMED_FILES=$(find "$TARGET_DIR" -type f -name "*$TARGET_PACKAGE*.sh" 2>/dev/null)
if [ -n "$PACKAGE_NAMED_FILES" ]; then
    for file in $PACKAGE_NAMED_FILES; do
        echo "❌ 发现目标包名命名的sh程序: $file"
        PACKAGE_FOUND=1
        echo "   文件信息:"
        ls -la "$file" 2>/dev/null | head -1
        echo "   文件大小: $(du -h "$file" | cut -f1)"
        echo ""
    done
else
    echo "✅ 未在$data/adb/下发现含 $TARGET_PACKAGE 包名的sh程序（文件名匹配）"
    echo ""
fi

# 5. 保留原逻辑：检测Magisk模块中含目标包名的脚本
echo "[5] 检测Magisk模块中含 $TARGET_PACKAGE 包名的脚本..."
MODULES_DIR="/data/adb/modules"
if [ -d "$MODULES_DIR" ]; then
    for module in "$MODULES_DIR"/*; do
        if [ -d "$module" ]; then
            module_name=$(basename "$module")
            for script in "$module/post-fs-data.sh" "$module/service.sh" "$module/install.sh"; do
                if [ -f "$script" ]; then
                    if grep -q -E "$TARGET_PACKAGE" "$script" 2>/dev/null; then
                        echo "❌ 模块 $module_name 的 $(basename "$script") 含目标包名"
                        PACKAGE_FOUND=1
                        echo "   文件路径: $script"
                        echo "   相关内容片段:"
                        grep -E "$TARGET_PACKAGE" "$script" | head -3
                        echo ""
                    fi
                fi
            done
        fi
    done
fi
if [ $PACKAGE_FOUND -eq 0 ] && [ -d "$MODULES_DIR" ]; then
    echo "✅ 未在Magisk模块中发现含 $TARGET_PACKAGE 包名的脚本"
    echo ""
fi

# ==========================================
# 汇总结果：分别汇报APK文件、包名程序、原生病毒的检测结果
# ==========================================
echo "=========================================="
echo "检测结果汇总（三目标检测）"
echo "=========================================="

# 汇报原生病毒（zygisk.apk/com.android.append）结果
if [ -n "$MALICIOUS_FOUND" ] && [ $MALICIOUS_FOUND -eq 1 ]; then
    echo "❌ 已发现原生恶意文件（zygisk.apk / com.android.append）"
else
    echo "✅ 未发现原生恶意文件（zygisk.apk / com.android.append）"
fi
echo ""

# 汇报目标APK（bin.mt.plus.termux.apk）结果
if [ $APK_FOUND -eq 1 ]; then
    echo "❌ 已在$data/adb/下发现 $TARGET_APK_NAME 文件！"
    echo "   处理建议:"
    echo "   - 立即删除检测到的APK文件（路径已在上文列出）"
    echo "   - 重启设备，避免APK残留进程运行"
else
    echo "✅ 未在$data/adb/下发现 $TARGET_APK_NAME 文件"
fi
echo ""

# 汇报目标包名程序（bin.mt.plus.termux相关sh）结果
if [ $PACKAGE_FOUND -eq 1 ]; then
    echo "❌ 已在$data/adb/下发现含 $TARGET_PACKAGE 包名的程序！"
    echo "   处理建议:"
    echo "   1. 确认相关sh程序是否为主动安装的可信程序"
    echo "   2. 未知程序建议立即删除对应的sh文件"
    echo "   3. 涉及Magisk模块则卸载可疑模块后重启"
    echo "   4. 必要时备份数据后清理/data/adb冗余文件"
else
    echo "✅ 未在$data/adb/下发现含 $TARGET_PACKAGE 包名的程序"
    echo ""
    echo "通用建议:"
    echo "• 定期扫描敏感目录，防范未知风险"
    echo "• 仅保留可信来源的Magisk模块及文件"
    echo "• 不刷未知来源模块，不执行陌生sh脚本"
    echo "• 定期保养手机，检查关键目录安全性"
fi
echo ""
echo "检测完成"
