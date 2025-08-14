#!/bin/bash

set -euo pipefail
set -x

apt update -y && apt install vim wget file less curl python3 grep python3-pip -y
wget https://github.com/canonical/chisel/releases/download/v1.1.0/chisel_v1.1.0_linux_amd64.tar.gz
mkdir -p /usr/bin/chisel-bin && tar -xvf chisel_v1.1.0_linux_amd64.tar.gz -C /usr/bin/chisel-bin
ln -sf /usr/bin/chisel-bin/chisel /usr/bin/chisel

pip3 install pyyaml --break-system-packages

mkdir -p foo-base slice_results

# Initial base cut
chisel cut --release chisel-releases/ --root foo-base apache2-bin_bins base-passwd_data
chroot foo-base apache2 -v

# Confirm apache2 runs with minimal config
mkdir -p foo-base/dev && mount --rbind /dev foo-base/dev
mkdir -p foo-base/etc/apache2 foo-base/etc/apache2/logs
mkdir -p foo-base/var/{run,lock,log}/apache2 foo-base/var/www/html
chown -R www-data:www-data foo-base/var
chmod -R 755 foo-base/var
chmod 755 foo-base

cat <<'EOF' > foo-base/etc/apache2/apache2.conf
DefaultRuntimeDir /var/run/apache2
ServerRoot "/etc/apache2"
ServerName localhost
Listen 127.0.0.1:8080
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
ErrorLog /etc/apache2/logs/error.log
User www-data
Group www-data
DocumentRoot "/var/www/html"
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF

echo "Hello, Apache!" > foo-base/var/www/html/index.html
chroot foo-base apache2 -f /etc/apache2/apache2.conf -D FOREGROUND &
APACHE_PID=$!
sleep 3
if test "$(curl -s -o /dev/null -w "%{http_code}" 127.0.0.1:8080)" = "200"; then
    echo "[OK] Apache is running"
else
    echo "[FAIL] Apache did not start"
    kill "$APACHE_PID" && wait "$APACHE_PID" 2>/dev/null || true
    umount -l foo-base/dev

fi
kill "$APACHE_PID" && wait "$APACHE_PID" 2>/dev/null || true
umount -l foo-base/dev

# Parallel slice testing
i=1
pids=""
for slice in chisel-releases/tests/spread/integration/apache2-bin/cases/*.deps; do
(
    slice_name=$(basename "$slice" .deps)
    module_name=$(echo "${slice_name#mod-}" | tr '-' '_')
    module_var=${module_name}_module
    file_name=$(echo "$slice_name" | tr '-' '_').so
    port=$((8080 + i))
    rootfs="foo-$slice_name"
    result_file="slice_results/${slice_name}_result.log"
    reason_file="slice_results/${slice_name}_reason.log"

    mkdir -p ${rootfs}
    deps=$(grep -v '^[[:space:]]*$' "$slice" | tr '\n' ' ')
    chisel cut --release chisel-releases/ --root "$rootfs" apache2-bin_mod-mpm-prefork \
    apache2-bin_mod-authz-core apache2-bin_${slice_name} base-passwd_data $deps
    cp "$slice" "$rootfs/"

    mkdir -p "$rootfs"/dev "$rootfs"/proc
    mount --rbind /dev "$rootfs"/dev
    mount -t proc proc "$rootfs"/proc
    mkdir -p "$rootfs"/etc/apache2 "$rootfs"/etc/apache2/logs
    mkdir -p "$rootfs"/var/{run,lock,log}/apache2 "$rootfs"/var/www/html
    chown -R www-data:www-data "$rootfs"/var
    chmod -R 755 "$rootfs"/var
    chmod 755 "$rootfs"

    touch "${rootfs}/etc/apache2/mime.types"

    cat <<EOF > "$rootfs/etc/apache2/apache2.conf"
DefaultRuntimeDir /var/run/apache2
ServerRoot "/etc/apache2"
ServerName localhost
Listen 127.0.0.1:$port
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
EOF
    if [ -f "$slice" ]; then
        while read -r dep; do
            [ -z "$dep" ] && continue
            if echo "$dep" | grep -q 'mod-'; then
                mod_name=$(echo "$dep" | sed -n 's/.*mod-\(.*\)/\1/p' | tr '-' '_')
                mod_var="${mod_name}_module"
                mod_file="mod_${mod_name}.so"
                echo "LoadModule $mod_var /usr/lib/apache2/modules/$mod_file" >> "${rootfs}/etc/apache2/apache2.conf"
            fi
        done < "$slice"
    fi


    main_mod_name="${slice_name#mod-}"
    main_mod_var="${main_mod_name//-/_}_module"
    main_mod_file="mod_${main_mod_name//-/_}.so"
    echo $main_mod_name $main_mod_var $main_mod_file
    echo "LoadModule $main_mod_var /usr/lib/apache2/modules/$main_mod_file" >> "${rootfs}/etc/apache2/apache2.conf"

    cat <<EOF >> "${rootfs}/etc/apache2/apache2.conf"
ErrorLog /etc/apache2/logs/error.log
User www-data
Group www-data
DocumentRoot "/var/www/html"
<Directory "/var/www/html">
    AllowOverride None
    Require all granted
</Directory>
EOF
    echo "Hello, Apache!" > "$rootfs/var/www/html/index.html"

    if ! chroot "$rootfs" apache2 -f /etc/apache2/apache2.conf -M | grep -q "$module_var"; then
        echo "fail" > "$result_file"
        echo "❌ $slice_name: Module $module_var failed to load." > "$reason_file"
        umount -l "$rootfs"/dev
        umount -l "$rootfs"/proc

    fi
    chroot "$rootfs" apache2 -f /etc/apache2/apache2.conf -k start > "$rootfs/apache_start.log" 2>&1 &
    sleep 3

    if ! test "$(curl -s -o /dev/null -w "%{http_code}" 127.0.0.1:$port/index.html)" = "200"; then
        echo "fail" > "$result_file"
        echo "❌ $slice_name: Apache failed HTTP 200 check on port $port" > "$reason_file"
        cat "$rootfs/apache_start.log" >> "$reason_file"
        if [ -f "$rootfs/var/log/apache2/error.log" ]; then
            echo -e "\n--- Apache Error Log ---" >> "$reason_file"
            cat "$rootfs/etc/apache2/logs/error.log" >> "$reason_file"
        fi
        chroot "$rootfs" apache2 -k stop || true
        umount -l "$rootfs"/dev
        umount -l "$rootfs"/proc

    fi

    echo "ok" > "$result_file"
    chroot "$rootfs" apache2 -k stop
    umount -l "$rootfs"/dev
    umount -l "$rootfs"/proc
    #rm -rf "$rootfs"
) &
pids="$pids $!"
i=$((i + 1))
done

fail=0
for pid in $pids; do
    wait $pid || fail=1
done

echo "\n[SUMMARY]"
for result in slice_results/*; do
    slice=$(basename "$result")
    status=$(cat "$result")
    if [ "$status" = "ok" ]; then
        echo "✅ PASSED: $slice"
    else
        echo "❌ FAILED: $slice"
        if [ -f "slice_results/$slice.reason" ]; then
            sed 's/^/    /' "slice_results/$slice.reason"
        fi
    fi
done

if [ "$fail" -ne 0 ]; then
    echo -e "\n[ERROR] One or more slices failed."

else
    echo -e "\n[SUCCESS] All slice tests passed."
fi
