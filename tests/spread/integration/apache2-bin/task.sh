#!/bin/bash

apt update
apt update -y && apt install wget file less curl python3 grep python3-pip -y && wget https://github.com/canonical/chisel/releases/download/v1.1.0/chisel_v1.1.0_linux_amd64.tar.gz && tar -xvf chisel_v1.1.0_linux_amd64.tar.gz  -C /usr/bin/ chisel
pip3 install pyyaml --break-system-packages
mkdir foo

chisel cut --release chisel-releases/ --root foo apache2-bin_bins base-passwd_data

chroot foo apache2 -v

mkdir -p foo/dev
mount --rbind /dev foo/dev
mkdir -p foo/etc/apache2
mkdir -p foo/etc/apache2/logs
mkdir -p foo/var/run/apache2
mkdir -p foo/var/lock/apache2
mkdir -p foo/var/log/apache2
mkdir -p foo/var/www/html

chown www-data:www-data foo/var/run/apache2
chown www-data:www-data foo/var/lock/apache2
chown www-data:www-data foo/var/log/apache2
chown -R www-data:www-data foo/var/www

chmod 755 foo/var/run/apache2
chmod 755 foo/var/lock/apache2
chmod 755 foo/var/log/apache2
chmod -R 755 foo/var/www
chmod 755 foo

cat <<'EOF' > "foo/etc/apache2/apache2.conf"
DefaultRuntimeDir /var/run/apache2
ServerRoot "/etc/apache2"
ServerName localhost
Listen 0.0.0.0:8080
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

echo "Hello, Apache!" > foo/var/www/html/index.html
test "$(chroot "foo" apache2 -t 2>&1 )" = "Syntax OK"
chroot foo apache2 -f /etc/apache2/apache2.conf -D FOREGROUND &
APACHE_PID=$!
sleep 10
if test "$(curl -s -o /dev/null -w "%{http_code}\n" 127.0.0.1:8080)" = "200";
then
    echo "[OK] Apache is running"
else
    echo "[FAIL] Apache did not start"
    #exit 1
fi
kill "$APACHE_PID"
wait "$APACHE_PID" 2>/dev/null || true
umount -l foo/dev
python3 chisel-releases/tests/spread/integration/apache2-bin/prepare_tests_imports.py
for slice in $(ls chisel-releases/tests/spread/integration/apache2-bin/cases/*.deps); do
    slice_name=$(basename "$slice" .deps)
    module_name=$(echo "${slice_name#mod-}" | tr '-' '_')
    module_var=${module_name}_module
    file_name=$(echo "$slice_name" | tr '-' '_').so
    deps=$(grep -v '^[[:space:]]*$' "chisel-releases/tests/spread/integration/apache2-bin/cases/$slice_name.deps" | tr '\n' ' ')
    chisel cut --release chisel-releases/ --root foo apache2-bin_${slice_name} apache2-bin_bins base-passwd_data $deps
    #rootfs=$(install-slices apache2-bin_${slice_name} apache2-bin_bins \
            #base-passwd_data $deps)
    cp /chisel-releases/tests/spread/integration/apache2-bin/cases/$slice_name.deps foo

    pkill -f "chroot foo apache2" 2>/dev/null || true
    umount -l foo/dev 2>/dev/null || true
    umount -l foo/proc 2>/dev/null || true

    mkdir -p foo/dev foo/proc
    mount --rbind /dev foo/dev
    mount -t proc proc foo/proc
    mkdir -p foo/etc/apache2
    mkdir -p foo/etc/apache2/logs
    mkdir -p foo/var/run/apache2
    mkdir -p foo/var/lock/apache2
    mkdir -p foo/var/log/apache2
    mkdir -p foo/var/www/html

    chown www-data:www-data foo/var/run/apache2
    chown www-data:www-data foo/var/lock/apache2
    chown www-data:www-data foo/var/log/apache2
    chown -R www-data:www-data foo/var/www

    chmod 755 foo/var/run/apache2
    chmod 755 foo/var/lock/apache2
    chmod 755 foo/var/log/apache2
    chmod -R 755 foo/var/www
    chmod 755 foo

    cat <<EOF > "foo/etc/apache2/apache2.conf"
DefaultRuntimeDir /var/run/apache2
ServerRoot "/etc/apache2"
ServerName localhost
Listen 0.0.0.0:8080
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule $module_var /usr/lib/apache2/modules/${file_name}
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
    echo "Hello, Apache!" > "foo/var/www/html/index.html"
    if chroot foo apache2 -f /etc/apache2/apache2.conf -M | grep -q "$module_var"; then
        echo "[OK] $slice_name loaded"
    else
        echo "[FAIL] $slice_name not loaded"
        #exit 1
    fi
    chroot foo apache2 -f /etc/apache2/apache2.conf -D FOREGROUND &
    APACHE_PID=$!
    sleep 10
    if test "$(curl -s -o /dev/null -w "%{http_code}" 127.0.0.1:8080)" = "200"; then
        echo "[OK] Apache responded for $slice_name"
    else
        echo "[FAIL] Apache did not respond for $slice_name"
        echo "--- Begin apache2 error log ---"
        cat foo/etc/apache2/logs/error.log || echo "(no log found)"
        echo "--- End apache2 error log ---"
        kill "$APACHE_PID" 2>/dev/null || true
        wait "$APACHE_PID" 2>/dev/null || true
        #exit 1
    fi

    kill "$APACHE_PID" 2>/dev/null || true
    wait "$APACHE_PID" 2>/dev/null || true
    umount -l foo/dev
    umount -l foo/proc
done
