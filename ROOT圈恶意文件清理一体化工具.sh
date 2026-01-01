#!/system/bin/sh
# 核心目标配置
TARGET_PACKAGE="bin.mt.plus.termux"          # 目标包名
TARGET_APK_NAME="bin.mt.plus.termux.apk"     # 目标APK文件名
MALICIOUS_MARKERS="zygisk.apk com.android.append"  # 原生恶意文件标记（用空格分隔，兼容sh）
# 路径配置（修复日志文件写入权限问题）
TARGET_DIR="/data/adb"
MODULES_DIR="${TARGET_DIR}/modules"
LOG_FILE="/sdcard/Android/virus_scan_delete.log"  # 日志保存到SD卡，避免权限问题
BACKUP_LOG_FILE="/data/local/tmp/virus_scan_delete.log"  # 日志降级路径
# 安全配置
EXCLUDE_FILES="ROOT圈病毒一体化工具.sh 检测脚本.sh 1.sh"  # 防误删文件（用空格分隔）
MAX_RETRY=2  # 删除失败重试次数
DELAY=1      # 重试延迟（秒）

# ========================= 工具函数定义（sh兼容版）=========================
# 1. 彩色输出函数（增强可读性，兼容无颜色终端）
color_echo() {
    local color="$1"
    local text="$2"
    # 仅在终端支持时输出颜色（避免日志乱码）
    if [ -t 1 ]; then
        case "$color" in
            red)    echo -e "\033[31m${text}\033[0m" ;;
            green)  echo -e "\033[32m${text}\033[0m" ;;
            yellow) echo -e "\033[33m${text}\033[0m" ;;
            blue)   echo -e "\033[34m${text}\033[0m" ;;
            *)      echo "${text}" ;;
        esac
    else
        echo "${text}"
    fi
}

# 2. 日志记录函数（支持降级，避免丢失）
log_record() {
    local level="$1"
    local content="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_content="[$timestamp] [$level] $content"
    
    # 优先写入SD卡日志，失败则降级到/data/local/tmp
    if echo "${log_content}" >> "${LOG_FILE}" 2>/dev/null; then
        :
    else
        mkdir -p "$(dirname "${BACKUP_LOG_FILE}")" 2>/dev/null
        echo "${log_content}" >> "${BACKUP_LOG_FILE}" 2>/dev/null
    fi

    # 终端同步输出
    case "$level" in
        INFO)  color_echo blue "ℹ️  $content" ;;
        WARN)  color_echo yellow "⚠️  $content" ;;
        ERROR) color_echo red "❌ $content" ;;
        SUCCESS) color_echo green "✅ $content" ;;
        *) color_echo "" "$content" ;;
    esac
}

# 3. 权限校验函数（增强兼容性+SELinux提示+自身排除）
check_permission() {
    log_record INFO "正在校验root权限..."
    if [ "$(id -u)" -ne 0 ]; then
        log_record ERROR "未获取root权限！检测和删除操作均需root权限"
        log_record INFO "请执行 su 命令获取root权限后重新运行脚本"
        exit 1
    fi
    log_record SUCCESS "已获取root权限"

    # 校验目标目录访问权限
    if [ -d "${TARGET_DIR}" ] && [ ! -r "${TARGET_DIR}" ] && [ ! -x "${TARGET_DIR}" ]; then
        log_record ERROR "无 ${TARGET_DIR} 目录访问权限，请检查selinux或root完整性"
        log_record WARN "建议尝试：su -c 'setenforce 0'（临时关闭SELinux）"
        exit 1
    fi

    # SELinux状态提示（兼容getenforce不可用场景）
    local selinux_status
    selinux_status=$(getenforce 2>/dev/null)
    if [ "${selinux_status}" = "Enforcing" ]; then
        log_record WARN "SELinux处于严格模式，可能导致文件删除失败"
        log_record INFO "临时关闭命令：su -c 'setenforce 0'（结束后可恢复：setenforce 1）"
    fi

    # 排除脚本自身（避免自我检测/误删）
    local SCRIPT_PATH
    SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || echo "$0")
    EXCLUDE_FILES="${EXCLUDE_FILES} $(basename "${SCRIPT_PATH}") ${SCRIPT_PATH}"
}

# 4. 检查文件是否在排除列表（兼容sh字符串遍历）
is_excluded() {
    local target="$1"
    local ex_file
    for ex_file in ${EXCLUDE_FILES}; do
        if [ "${target}" = "${ex_file}" ] || [ "$(basename "${target}")" = "${ex_file}" ]; then
            return 0  # 在排除列表中
        fi
    done
    return 1  # 不在排除列表中
}

# 5. 文件去重函数（支持含空格路径，用换行分隔）
deduplicate_list() {
    printf "%s\n" "$@" | awk '!seen[$0]++'
}

# 6. 安全删除函数（完善符号链接处理+重试机制，兼容sh）
safe_delete() {
    local target="$1"
    local retry_count=0
    local delete_success=0
    
    # 处理符号链接（避免误删系统文件/残留恶意链接）
    if [ -L "${target}" ]; then
        local link_target
        link_target=$(readlink -f "${target}" 2>/dev/null || echo "${target}")
        # 拒绝删除指向系统核心目录的链接
        if echo "${link_target}" | grep -qE "^/system|^/vendor|^/odm|^/boot"; then
            log_record ERROR "拒绝删除：${target} 指向系统目录（${link_target}），可能导致设备异常"
            return 1
        fi
        # 删除恶意文件创建的符号链接
        if echo "${target}" | grep -qE "${MALICIOUS_MARKERS}" || echo "${link_target}" | grep -qE "${TARGET_PACKAGE}"; then
            log_record INFO "删除恶意符号链接：${target}（指向 ${link_target}）"
            rm -rf "${target}" 2>/dev/null
            if [ ! -L "${target}" ]; then
                log_record SUCCESS "符号链接删除成功"
            else
                log_record ERROR "符号链接删除失败"
            fi
            return 0
        fi
        log_record WARN "跳过删除：${target} 是良性符号链接（指向 ${link_target}）"
        return 0
    fi
    
    # 跳过不存在的目标
    if [ ! -e "${target}" ]; then
        log_record WARN "跳过删除：${target} 已不存在"
        return 0
    fi

    # 执行删除（支持重试，用$((...))兼容sh算术）
    while [ "${retry_count}" -lt "${MAX_RETRY}" ]; do
        local current_try
        current_try=$((retry_count + 1))
        log_record INFO "正在删除目标（第 ${current_try} 次）：${target}"
        rm -rf "${target}" 2>/dev/null
        
        # 验证删除结果
        if [ ! -d "${target}" ] && [ ! -f "${target}" ] && [ ! -L "${target}" ]; then
            log_record SUCCESS "删除成功：${target}"
            delete_success=1
            break
        else
            log_record WARN "删除失败，${DELAY}秒后重试..."
            sleep "${DELAY}"
            retry_count=$((retry_count + 1))
        fi
    done

    # 最终失败提示
    if [ "${delete_success}" -eq 0 ]; then
        log_record ERROR "删除失败（已重试${MAX_RETRY}次）：${target}"
        log_record ERROR "可能原因：文件被占用、selinux限制、root权限不完整"
    fi
}

# 7. AAPT工具适配函数（Termux自动安装）
find_aapt() {
    local aapt_paths
    aapt_paths="/system/bin/aapt /system/xbin/aapt /data/adb/magisk/busybox/aapt /data/local/bin/aapt /data/data/com.termux/files/usr/bin/aapt"
    local path
    for path in ${aapt_paths}; do
        if [ -x "${path}" ]; then
            echo "${path}"
            return 0
        fi
    done
    # Termux环境自动安装aapt
    if command -v pkg &>/dev/null; then
        log_record WARN "未找到aapt工具，尝试自动安装（需网络）..."
        pkg install -y aapt 2>/dev/null
        if [ -x "/data/data/com.termux/files/usr/bin/aapt" ]; then
            log_record SUCCESS "aapt安装成功"
            echo "/data/data/com.termux/files/usr/bin/aapt"
            return 0
        fi
    fi
    echo ""
}

# ========================= 主程序入口 =========================
# 1. 初始化（标题+日志目录）
clear
echo "=========================================="
color_echo blue "  ROOT圈病毒一体化工具（sh兼容版）"
color_echo blue "  开发：小悦 | 绿色开源 | 精准杀戮"
echo "=========================================="
# 创建日志目录（若不存在）
mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null
mkdir -p "$(dirname "${BACKUP_LOG_FILE}")" 2>/dev/null
log_record INFO "===== 工具启动 ====="
# 兼容getprop不可用场景
local device_model android_version
if command -v getprop &>/dev/null; then
    device_model=$(getprop ro.product.model)
    android_version=$(getprop ro.build.version.release)
else
    device_model="未知（未找到getprop工具）"
    android_version="未知（未找到getprop工具）"
fi
log_record INFO "设备型号：${device_model}"
log_record INFO "Android版本：${android_version}"
log_record INFO "脚本版本：v2.5（sh兼容最终版）"
echo ""

# 2. 权限校验
check_permission
# 兼容老旧Shell，不支持nullglob则跳过（避免报错）
if shopt -q nullglob 2>/dev/null; then
    shopt -s nullglob
else
    log_record WARN "当前Shell不支持nullglob，部分通配符匹配可能异常"
fi
echo ""

# 3. 初始化检测状态（用普通变量替代数组，兼容sh）
DELETABLE_TARGETS=""  # 可删除目标列表（用换行分隔）
APK_FOUND=0           # 目标APK检测标记
PACKAGE_SCRIPT_FOUND=0# 包名相关脚本检测标记
MALICIOUS_FOUND=0     # 原生恶意文件检测标记

# ========================= 核心检测逻辑（sh兼容版）=========================
log_record INFO "===== 开始全维度检测 ====="
echo ""

# 3.1 检测原生恶意文件（zygisk.apk/com.android.append）
log_record INFO "【1/5】检测原生恶意文件..."
local malicious_paths
malicious_paths="/system/priv-apk/zygisk/zygisk.apk ${MODULES_DIR}/*/system/priv-apk/zygisk/zygisk.apk /data/app/com.android.append* /data/data/com.android.append /data/adb/modules/*/zygisk.apk"
local path
for path in ${malicious_paths}; do
    # 用find+print0处理含空格路径，避免拆分
    find "$(dirname "${path}")" -maxdepth 1 -name "$(basename "${path}")" -print0 2>/dev/null | while read -d '' file; do
        if [ -e "${file}" ]; then
            MALICIOUS_FOUND=1
            # 用换行分隔目标，避免空格拆分
            DELETABLE_TARGETS="${DELETABLE_TARGETS}${file}\n"
            
            # 详细文件信息
            log_record ERROR "发现原生恶意文件：${file}"
            echo "   文件类型：$(if [ -d "${file}" ]; then echo "目录"; else echo "文件"; fi)"
            ls -la "${file}" 2>/dev/null | head -1 | awk '{print "   权限："$1"  大小："$5"  修改时间："$6" "$7" "$8}'
            if [ -f "${file}" ]; then
                echo "   文件大小：$(du -h "${file}" 2>/dev/null | cut -f1)"
            fi
            echo ""
        fi
    done
done
if [ "${MALICIOUS_FOUND}" -eq 0 ]; then
    log_record SUCCESS "未发现原生恶意文件（${MALICIOUS_MARKERS}）"
fi
echo ""

# 3.2 检测目标APK（递归搜索，支持含空格路径）
log_record INFO "【2/5】检测 ${TARGET_APK_NAME} 文件（递归搜索）..."
local AAPT_PATH
AAPT_PATH=$(find_aapt)
if [ -d "${TARGET_DIR}" ]; then
    # 用find+print0避免空格拆分路径
    find "${TARGET_DIR}" -type f -name "${TARGET_APK_NAME}" -print0 2>/dev/null | while read -d '' apk_file; do
        APK_FOUND=1
        DELETABLE_TARGETS="${DELETABLE_TARGETS}${apk_file}\n"
        
        log_record ERROR "发现目标APK文件：${apk_file}"
        echo "   文件信息："
        ls -la "${apk_file}" 2>/dev/null | head -1 | awk '{print "   权限："$1"  大小："$5"  修改时间："$6" "$7" "$8}'
        echo "   文件大小：$(du -h "${apk_file}" 2>/dev/null | cut -f1)"
        # 获取APK版本
        if [ -n "${AAPT_PATH}" ]; then
            local apk_version
            apk_version=$("${AAPT_PATH}" dump badging "${apk_file}" 2>/dev/null | grep "versionName" | head -1 | awk -F"'" '{print $2}')
            echo "   APK版本：${apk_version:-未知}"
        else
            echo "   APK版本：未安装aapt，无法获取"
        fi
        echo ""
    done
    
    if [ "${APK_FOUND}" -eq 0 ]; then
        log_record SUCCESS "未在 ${TARGET_DIR} 下发现 ${TARGET_APK_NAME} 文件"
    fi
else
    log_record WARN "跳过APK检测：${TARGET_DIR} 目录不存在"
fi
echo ""

# 3.3 检测含目标包名的sh程序（内容匹配，排除例外）
log_record INFO "【3/5】检测含 ${TARGET_PACKAGE} 包名的sh程序（内容匹配）..."
if [ -d "${TARGET_DIR}" ]; then
    # 用find+print0处理含空格路径
    find "${TARGET_DIR}" -type f -name "*.sh" -print0 2>/dev/null | while read -d '' sh_file; do
        local file_name
        file_name=$(basename "${sh_file}")
        local file_path
        file_path=$(readlink -f "${sh_file}" 2>/dev/null || echo "${sh_file}")
        local exclude=0
        
        # 检查是否在例外列表
        if is_excluded "${sh_file}" || is_excluded "${file_path}"; then
            exclude=1
        fi
        
        # 内容匹配检测
        if [ "${exclude}" -eq 0 ] && grep -q -E "${TARGET_PACKAGE}" "${sh_file}" 2>/dev/null; then
            PACKAGE_SCRIPT_FOUND=1
            DELETABLE_TARGETS="${DELETABLE_TARGETS}${sh_file}\n"
            
            log_record ERROR "发现含目标包名的sh程序：${sh_file}"
            echo "   文件信息："
            ls -la "${sh_file}" 2>/dev/null | head -1 | awk '{print "   权限："$1"  大小："$5"  修改时间："$6" "$7" "$8}'
            echo "   文件大小：$(du -h "${sh_file}" 2>/dev/null | cut -f1)"
            echo "   相关内容片段："
            grep -E "${TARGET_PACKAGE}" "${sh_file}" 2>/dev/null | head -3 | sed 's/^/     /'
            echo ""
        fi
    done
    
    if [ "${PACKAGE_SCRIPT_FOUND}" -eq 0 ]; then
        log_record SUCCESS "未发现含 ${TARGET_PACKAGE} 包名的sh程序（已排除例外文件）"
    fi
else
    log_record WARN "跳过sh程序检测：${TARGET_DIR} 目录不存在"
fi
echo ""

# 3.4 检测目标包名命名的sh程序（文件名匹配）
log_record INFO "【4/5】检测含 ${TARGET_PACKAGE} 包名的sh程序（文件名匹配）..."
if [ -d "${TARGET_DIR}" ]; then
    # 用find+print0处理含空格路径
    find "${TARGET_DIR}" -type f -name "*${TARGET_PACKAGE}*.sh" -print0 2>/dev/null | while read -d '' file; do
        local file_name
        file_name=$(basename "${file}")
        local file_path
        file_path=$(readlink -f "${file}" 2>/dev/null || echo "${file}")
        local exclude=0
        
        # 检查是否在例外列表
        if is_excluded "${file}" || is_excluded "${file_path}"; then
            exclude=1
        fi
        
        if [ "${exclude}" -eq 0 ]; then
            PACKAGE_SCRIPT_FOUND=1
            DELETABLE_TARGETS="${DELETABLE_TARGETS}${file}\n"
            
            log_record ERROR "发现目标包名命名的sh程序：${file}"
            echo "   文件信息："
            ls -la "${file}" 2>/dev/null | head -1 | awk '{print "   权限："$1"  大小："$5"  修改时间："$6" "$7" "$8}'
            echo "   文件大小：$(du -h "${file}" 2>/dev/null | cut -f1)"
            echo ""
        fi
    done
    
    if [ "${PACKAGE_SCRIPT_FOUND}" -eq 0 ]; then
        log_record SUCCESS "未发现含 ${TARGET_PACKAGE} 包名的sh程序（文件名匹配）"
    fi
else
    log_record WARN "跳过文件名匹配检测：${TARGET_DIR} 目录不存在"
fi
echo ""

# 3.5 检测Magisk模块中的可疑脚本
log_record INFO "【5/5】检测Magisk模块中含 ${TARGET_PACKAGE} 包名的脚本..."
if [ -d "${MODULES_DIR}" ]; then
    # 用find+print0处理含空格模块名
    find "${MODULES_DIR}" -maxdepth 1 -type d ! -name "modules" -print0 2>/dev/null | while read -d '' module; do
        local module_name
        module_name=$(basename "${module}")
        local module_scripts
        module_scripts="${module}/post-fs-data.sh ${module}/service.sh ${module}/install.sh ${module}/uninstall.sh"
        
        local script
        for script in ${module_scripts}; do
            if [ -f "${script}" ] && grep -q -E "${TARGET_PACKAGE}" "${script}" 2>/dev/null; then
                PACKAGE_SCRIPT_FOUND=1
                DELETABLE_TARGETS="${DELETABLE_TARGETS}${script}\n"
                
                log_record ERROR "模块 ${module_name} 存在可疑脚本：$(basename "${script}")"
                echo "   文件路径：${script}"
                echo "   相关内容片段："
                grep -E "${TARGET_PACKAGE}" "${script}" 2>/dev/null | head -3 | sed 's/^/     /'
                echo ""
            fi
        done
    done
    
    if [ "${PACKAGE_SCRIPT_FOUND}" -eq 0 ]; then
        log_record SUCCESS "未在Magisk模块中发现可疑脚本"
    fi
elif [ -d "${TARGET_DIR}" ] && [ ! -d "${MODULES_DIR}" ]; then
    log_record WARN "跳过模块检测：未找到Magisk模块目录（${MODULES_DIR}）"
else
    log_record WARN "跳过模块检测：${TARGET_DIR} 目录不存在"
fi
echo ""

# ========================= 检测结果汇总 =========================
log_record INFO "===== 检测结果汇总 ====="
echo "=========================================="
color_echo blue "检测结果汇总"
echo "=========================================="
if [ "${MALICIOUS_FOUND}" -eq 1 ]; then
    color_echo red "❌ 原生恶意文件：已发现（${MALICIOUS_MARKERS}）"
    color_echo red "   风险等级：高危（可能窃取隐私/篡改系统）"
else
    color_echo green "✅ 原生恶意文件：未发现"
fi
if [ "${APK_FOUND}" -eq 1 ]; then
    color_echo red "❌ 目标APK文件：已发现（${TARGET_APK_NAME}）"
else
    color_echo green "✅ 目标APK文件：未发现"
fi
if [ "${PACKAGE_SCRIPT_FOUND}" -eq 1 ]; then
    color_echo red "❌ 可疑脚本文件：已发现（含 ${TARGET_PACKAGE} 包名）"
else
    color_echo green "✅ 可疑脚本文件：未发现"
fi
echo "=========================================="
echo ""

# ========================= 核心删除逻辑（sh兼容版）=========================
# 去重可删除目标列表（用换行分隔，避免空格拆分）
local unique_targets
unique_targets=$(deduplicate_list "${DELETABLE_TARGETS}")
# 统计目标数量（兼容sh的字符串计数）
local target_count
target_count=$(echo -e "${unique_targets}" | grep -c .)

# 无目标时退出
if [ "${target_count}" -eq 0 ]; then
    log_record SUCCESS "===== 操作终止 ====="
    color_echo green "📌 未检测到任何可删除目标，设备当前无相关风险"
    echo ""
    log_record INFO "综合安全建议："
    log_record INFO "1. 定期运行本工具扫描，防范恶意文件植入"
    log_record INFO "2. 仅安装知名作者的Magisk模块，拒绝陌生来源文件"
    log_record INFO "3. 不执行陌生su命令，谨慎授予root权限"
    log_record INFO "相信张三丰，安全无烦恼～"
    exit 0
fi

# 展示可删除目标清单（分页优化）
log_record INFO "===== 可删除目标清单（共 ${target_count} 个）====="
color_echo yellow "⚠️  本次检测共发现 ${target_count} 个可疑目标："
local index=0
# 用while循环遍历目标（避免for循环拆分空格）
echo -e "${unique_targets}" | while read -r target; do
    if [ -n "${target}" ]; then
        index=$((index + 1))
        echo "${index}. ${target}"
        # 每5个目标暂停一次，避免刷屏
        if [ $((index % 5)) -eq 0 ] && [ "${index}" -ne "${target_count}" ]; then
            read -p "按回车键继续查看..." -n 1 -s
            echo ""
        fi
    fi
done
echo ""

# 安全确认（二次确认，防误操作）
color_echo red "⚠️  警告：删除后不可恢复！仅删除上述列出的目标，不影响其他系统/用户文件"
read -p "是否执行删除操作？(yes=删除 / no=保留，默认no)：" CHOICE
case "${CHOICE}" in
    [Yy][Ee][Ss]|Y|y)
        # 二次严格确认
        read -p "🔴 确认要永久删除所有可疑目标？再次输入 yes 确认（其他取消）：" CONFIRM
        if [ "${CONFIRM}" != "yes" ] && [ "${CONFIRM}" != "YES" ] && [ "${CONFIRM}" != "Yes" ]; then
            log_record WARN "===== 操作取消 ====="
            color_echo yellow "🛡️  二次确认取消，所有目标均保留"
            exit 0
        fi
        
        # 执行批量删除
        log_record INFO "===== 开始执行删除操作 ====="
        color_echo blue "🗑️  正在执行删除操作（支持自动重试）..."
        echo ""
        # 用while循环遍历目标，避免空格拆分
        echo -e "${unique_targets}" | while read -r target; do
            if [ -n "${target}" ]; then
                safe_delete "${target}"
            fi
        done
        
        log_record SUCCESS "===== 删除操作完成 ====="
        # 提示实际日志路径
        if [ -f "${LOG_FILE}" ]; then
            color_echo green "📌 所有目标处理完毕！详细结果请查看日志：${LOG_FILE}"
        else
            color_echo green "📌 所有目标处理完毕！详细结果请查看日志：${BACKUP_LOG_FILE}"
        fi
        ;;
    *)
        log_record WARN "===== 操作取消 ====="
        color_echo yellow "🛡️  已选择保留，所有目标均不删除"
        ;;
esac

# ========================= 最终安全建议 =========================
echo -e "\n=========================================="
color_echo blue "综合安全建议"
echo "=========================================="
log_record INFO "综合安全建议："
log_record INFO "1. 若删除了原生恶意文件，建议备份重要数据后刷机处理，彻底清除残留"
log_record INFO "2. 解绑敏感账号（银行卡、微信/QQ/支付宝），修改所有重要密码"
log_record INFO "3. 重启设备后，建议重新运行本工具扫描，确认无残留"
log_record INFO "4. 避免安装来源不明的Magisk模块、APK文件，拒绝陌生su命令"
log_record INFO "5. 定期检查 /data/adb 目录，及时清理可疑文件"
log_record INFO "相信张三丰，root设备安全无忧～"
log_record INFO "===== 工具运行结束 ====="
echo ""

# 提示最终日志路径
if [ -f "${LOG_FILE}" ]; then
    color_echo green "🎉 工具运行完成！日志文件已保存至：${LOG_FILE}"
else
    color_echo green "🎉 工具运行完成！日志文件已保存至：${BACKUP_LOG_FILE}"
fi
