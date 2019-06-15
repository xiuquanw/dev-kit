#!/bin/bash
# Author:  aidenpro.wang@gmail.com
# BLOG:  https://aiden.dev
#
# Notes: Initialize nginx/mysql/php environment on CentOS
#

export PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
clear
printf "
#######################################################################
#       Initialize nginx/mysql/php environment on CentOS        #
#       Find out more at https://aiden.dev                      #
#######################################################################
"
# Check if user is root
[ $(id -u) != "0" ] && { echo "${CFAILURE}Error: You must be root to run this script${CEND}"; exit 1; }

# Reset BASH time counter
SECONDS=0

# workspace
workspace=$(pwd)
echo "Workspace:${workspace}"

# print OS info
cat /etc/*elease

# Close SELINUX
echo "Close SELINUX"
setenforce 0
sed -i 's/^SELINUX=.*$/SELINUX=disabled/' /etc/selinux/config

# Set timezone
echo "Set timezone"
export timezone=Australia/Adelaide
echo "timezone:${timezone}"
ln -sf /usr/share/zoneinfo/${timezone} /etc/localtime
date

echo "Update OS"
yum -y update && yum install -y epel-release zip unzip

# Install mysql 5.7
echo "Install mysql 5.7"
yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-9.noarch.rpm
yum install -y mysql-community-server

# start mysql service
echo "Start mysql service"
service mysqld start

# get Temporary root Password
root_temp_pass=$(grep 'A temporary password' /var/log/mysqld.log |tail -1 |awk '{split($0,a,": "); print a[2]}')

echo "root_temp_pass: "$root_temp_pass

# root pass 
root_pass=$(</dev/urandom tr -dc 'A-Za-z0-9!#$%()=@' | head -c 16  ; echo
)"#"

echo "root_pass: "$root_pass | tee ${workspace}/root_pass.txt

# generate mysql_secure_installation.sql
cat > mysql_secure_installation.sql << EOF
# Make sure that NOBODY can access the server without a password
SET PASSWORD = PASSWORD('${root_pass}');
# Kill the anonymous users
DELETE FROM mysql.user WHERE User='';
# disallow remote login for root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
# Kill off the demo database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
# Make our changes take effect
FLUSH PRIVILEGES;
EOF

mysql -uroot -p"$root_temp_pass" --connect-expired-password <mysql_secure_installation.sql

# boot start
echo "Enable mysql boot start"
systemctl enable mysqld

# check mysql version
echo "Check mysql version"
mysql -V

# check mysql status
echo "Check mysql status"
systemctl status -l mysqld

# Nginx setup
echo "Install nginx"

cat > /etc/yum.repos.d/nginx.repo << 'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/$releasever/$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
EOF

yum install -y nginx

# start nginx service
echo "Start nginx service"
systemctl start nginx

# check nginx status
echo "Check nginx status"
systemctl status nginx.service -l

# boot start
echo "Enable nginx boot start"
systemctl enable nginx

# check nginx version
echo "Check nginx version"
nginx -v

## general configruation
# backup /etc/nginx/nginx.conf
[ -e /etc/nginx/nginx.conf ] && mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf_bk
# mkdir snippets directory
[ ! -e "/etc/nginx/snippets" ] && mkdir /etc/nginx/snippets
# mkdir cache directory
[ ! -e "/var/cache/nginx/fastcgi" ] && mkdir -p /var/cache/nginx/fastcgi && chown -R nginx:nginx /var/cache/nginx/fastcgi

cat > /etc/nginx/snippets/security.conf << 'EOF'
######################## improved security ############################
# don't send the nginx version number in error pages and Server header
server_tokens off;

# turning off the X-Powered-By header
proxy_hide_header X-Powered-By;

# config to don't allow the browser to render the page inside an frame or iframe
add_header X-Frame-Options SAMEORIGIN;

# This header enables the Cross-site scripting (XSS) filter built into most recent web browsers.
add_header X-XSS-Protection "1; mode=block";

# disable content-type sniffing on some browsers.
add_header X-Content-Type-Options "nosniff";
EOF

cat > /etc/nginx/snippets/fastcgi_extra.conf << 'EOF'
fastcgi_connect_timeout 300;
fastcgi_send_timeout 300;
fastcgi_read_timeout 300;
fastcgi_buffer_size 64k;
fastcgi_buffers 4 64k;
fastcgi_busy_buffers_size 128k;
fastcgi_temp_file_write_size 128k;
fastcgi_intercept_errors off;
EOF

# put in server/location block
cat > /etc/nginx/snippets/fastcgi_cache_wordpress.conf << 'EOF'
fastcgi_cache_bypass $skip_cache;
fastcgi_no_cache $skip_cache;
fastcgi_cache WORDPRESS;
fastcgi_cache_valid 200 60m;
EOF

# put in http block
cat > /etc/nginx/snippets/fastcgi_cache_global_wordpress.conf << 'EOF'
# ---------------------------------------------------------------------
# FASTCGI GLOBAL CONFIGURATION - START
# ---------------------------------------------------------------------
# below lines must be outside server blocks to enable FastCGI cache for Nginx
# path can be anywhere, app name must be consistent, total size small enough to avoid RAM depletion

fastcgi_cache_path /var/cache/nginx/fastcgi levels=1:2 keys_zone=WORDPRESS:256m max_size=5g inactive=60m use_temp_path=off;
fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_cache_use_stale error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;

# ---------------------------------------------------------------------
# FASTCGI GLOBAL CONFIGURATION - END
# ---------------------------------------------------------------------
EOF

## cache wordpress configruation
cat > /etc/nginx/snippets/cache_rules_wordpress.conf << 'EOF'
# Caching
set $skip_cache 0;
 
# Do not cache POST requests - they should always go to PHP
if ($request_method = POST) {
    set $skip_cache 1;
}
 
# Do not cache URLs with a query string - they should always go to PHP
if ($query_string != "") {
    set $skip_cache 1;
}
 
# WooCommerce-specific cache skip rules
if ($request_uri ~* "/store.*|/cart.*|/my-account.*|/checkout.*|/addons.*") {
    set $skip_cache 1;
    set $skip_cache_reason WP_WooCommerce;
}
 
if ($cookie_woocommerce_items_in_cart) {
    set $skip_cache 1;
    set $skip_cache_reason WP_WooCommerce;
}
 
if ($request_uri ~* ("/cart.*")) {
    set $skip_cache 1;
}
 
# Don't cache URIs containing the following segments (admin panel, sitemaps, feeds, etc.)
if ($request_uri ~* "(/wp-admin/|/xmlrpc.php|/wp-(app|cron|login|register|mail).php|wp-.*.php|/feed/|index.php|wp-comments-popup.php|wp-links-opml.php|wp-locations.php|sitemap(_index)?.xml|[a-z0-9_-]+-sitemap([0-9]+)?.xml)") {
    set $skip_cache 1;
}

# Don't use the cache for logged-in users or recent commenters
if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {
    set $skip_cache 1;
}

# Custom header (HIT/BYPASS/MISS)
add_header X-FastCGI-Cache $upstream_cache_status;
EOF

## assets cache/expires configruation
cat > /etc/nginx/snippets/expires_headers.conf << 'EOF'
# Directives to send expires headers and turn off 404 error logging.
location ~* ^.+\.(eot|otf|woff|woff2|ttf|rss|atom|zip|tgz|gz|rar|bz2|doc|xls|exe|ppt|tar|mid|midi|wav|bmp|rtf)$ {
    access_log off;
    log_not_found off;
    expires max;
}

# Media: images, icons, video, audio send expires headers.
location ~* \.(?:jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm)$ {
  expires 1M;
  access_log off;
  add_header Cache-Control "public";
}

# CSS and Javascript send expires headers.
location ~* \.(?:css|js)$ {
  expires 10d;
  access_log off;
  add_header Cache-Control "public";
}

# HTML send expires headers.
location ~* \.(html)$ {
  expires 7d;
  access_log off;
  add_header Cache-Control "public";
}
EOF

cat > /etc/nginx/snippets/gzip.conf << 'EOF'
#Gzip Compression
gzip on;
gzip_buffers 16 8k;
gzip_comp_level 6;
gzip_http_version 1.1;
gzip_min_length 256;
gzip_proxied any;
gzip_vary on;
gzip_types
    text/xml application/xml application/atom+xml application/rss+xml application/xhtml+xml image/svg+xml
    text/javascript application/javascript application/x-javascript
    text/x-json application/json application/x-web-app-manifest+json
    text/css text/plain text/x-component
    font/opentype application/x-font-ttf application/vnd.ms-fontobject
    image/x-icon;
gzip_disable "MSIE [1-6]\.(?!.*SV1)";
EOF

cat > /etc/nginx/snippets/cloudflare.conf << 'EOF'
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 104.16.0.0/12;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2c0f:f248::/32;
set_real_ip_from 2a06:98c0::/29;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
EOF

cat > /etc/nginx/snippets/restrictions.conf << 'EOF'
# Restrictions
# Disable logging for favicon and robots.txt
location = /favicon.ico {
    log_not_found off;
    access_log off;
}

location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
    try_files $uri /index.php?$args;
}

# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac). except .well-known
location ~ /\.(?!well-known).* {
    deny all;
}

# Deny access to any files with a .php extension in the uploads directory
# Works in sub-directory installs and also in multisite network
location ~* /(?:uploads|files)/.*\.php$ {
    deny all;
}
# End Restrictions
EOF

# nginx.conf
cat > /etc/nginx/nginx.conf << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
  log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

  access_log  /var/log/nginx/access.log  main;
  include mime.types;
  default_type application/octet-stream;
  server_names_hash_bucket_size 128;
  client_header_buffer_size 32k;
  large_client_header_buffers 4 32k;
  client_max_body_size 100m;
  client_body_buffer_size 10m;
  sendfile on;
  tcp_nopush on;
  keepalive_timeout 120;
  tcp_nodelay on;
  types_hash_max_size 2048;

  # gzip compression
  include snippets/gzip.conf;

  # security configuration
  include snippets/security.conf;

  # cloudfare configuration
  include snippets/cloudflare.conf;

  # fast-cgi cache configruation
  include snippets/fastcgi_cache_global_wordpress.conf;
  
  # webp image optimizatin configuration
  map $http_accept $webp_suffix {
        default   "";
        "~*webp"  ".webp";
  }

  # vhosts
  include /etc/nginx/conf.d/*.conf;
}
EOF

## vhost sample
cat > /etc/nginx/conf.d/vhost.conf.sample << 'EOF'
server {
    listen 80;
    server_name domain_name_here;
    root "/var/www/domain_name_here";

    index index.html index.htm index.php;

    if ($http_x_forwarded_for ~ "^([^,]+)" ) {
        set $first_xff $1;
    }

    charset utf-8;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    access_log /var/log/nginx/domain_name_here-access.log;
    error_log  /var/log/nginx/domain_name_here-error.log error;

    sendfile off;
    client_max_body_size 100m;

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php7-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;

        include snippets/fastcgi_extra.conf;
        include snippets/fastcgi_cache_wordpress.conf;
    }

    # webp redirect
    location ~* ^(/wp-content/.+)\.(png|jpg|jpeg)$ {
       expires 1M;
       access_log off;
       add_header Cache-Control "public";
       add_header Vary Accept;
       try_files $uri$webp_suffix $uri =404;
    }

    include snippets/cache_rules_wordpress.conf;
    include snippets/expires_headers.conf;
    include snippets/restrictions.conf;
}
EOF

# test nginx configuration
echo "Test nginx configuration"
nginx -t

# restart service
echo "Restart nginx service"
systemctl restart nginx

# check nginx status
echo "Check nginx status"
systemctl status nginx.service -l

# PHP7.2 setup
yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum install -y yum-utils
yum-config-manager --enable remi-php72
# install
yum --enablerepo=remi-php72 install -y php php-common php-fpm
yum --enablerepo=remi-php72 install -y php-mysql php-pecl-memcache php-pecl-memcached php-gd php-curl php-mbstring php-mcrypt php-json php-intl php-exif php-tokenizer php-sockets php-xml php-pecl-apc php-cli php-pear php-pdo php-ldap php-zip php-fileinfo php-bcmath php-zip php-opcache

# check version
php -v

# Configure Opcache PHP Extension
# backup /etc/php.ini
[ -e /etc/php.ini ] && cp /etc/php.ini /etc/php.ini_bk

# check php config info
php -i | grep php.ini

# update configurations by using sed
# check config
egrep "date.timezone|memory_limit|upload_max_filesize|post_max_size|max_execution_time|max_input_time" /etc/php.ini

time_zone_escape=$(echo $timezone | sed 's/\//\\\//g')
# update values
sed -i.bak "s/^;date.timezone =.*/date.timezone = \"${time_zone_escape}\"/" /etc/php.ini
sed -i.bak '/^ *memory_limit/s/=.*/= 128M/' /etc/php.ini
sed -i.bak '/^ *upload_max_filesize/s/=.*/= 32M/' /etc/php.ini
sed -i.bak '/^ *post_max_size/s/=.*/= 32M/' /etc/php.ini
sed -i.bak '/^ *max_execution_time/s/=.*/= 300/' /etc/php.ini
sed -i.bak '/^ *max_input_time/s/=.*/= 300/' /etc/php.ini

# check updated values
egrep "date.timezone =|memory_limit|upload_max_filesize|post_max_size|max_execution_time|max_input_time =" /etc/php.ini

# backup php-fpm settings
[ -e /etc/php-fpm.d/www.conf ] && cp /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf_bk

if [ -e /etc/php-fpm.d/www.conf ]
then
    # update values by shell
    sed -i.bak '/^ *user/s/=.*/= nginx/' /etc/php-fpm.d/www.conf
    sed -i.bak '/^ *group/s/=.*/= nginx/' /etc/php-fpm.d/www.conf
    sed -i.bak '/^ *listen/s/=.*/= \/var\/run\/php7-fpm.sock/' /etc/php-fpm.d/www.conf
    sed -i.bak 's/^;listen.owner =.*/listen.owner = nginx/' /etc/php-fpm.d/www.conf
    sed -i.bak 's/^;listen.group =.*/listen.group = nginx/' /etc/php-fpm.d/www.conf
    sed -i.bak 's/^;listen.mode =.*/listen.mode = 0660/' /etc/php-fpm.d/www.conf

    egrep "user =|group =|listen =|listen.owner =|listen.group =|listen.mode =" /etc/php-fpm.d/www.conf

    # boot start
    echo "Enable php-fpm boot start"
    systemctl enable php-fpm

    ## start php-fpm
    echo "Start php-fpm service"
    systemctl start php-fpm
else
    echo "php-fpm configuration file not found"
fi

## change permissons of sessions dirs
chown -R nginx:nginx /var/lib/php

# Git setup
echo "Install Git"
# update git
yum remove git
rpm -U https://centos7.iuscommunity.org/ius-release.rpm
yum install -y git2u

# check services status
systemctl status mysqld -l
systemctl status nginx.service -l
systemctl status php-fpm.service -l

ELAPSED="RunTime: $(($SECONDS / 3600))hrs $((($SECONDS / 60) % 60))min $(($SECONDS % 60))sec"

echo "====================================="
echo "Installation is complete."
echo $ELAPSED
echo "====================================="