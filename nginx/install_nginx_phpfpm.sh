#!/bin/bash
# This script will install Nginx webserver with PHP-FPM engine on different Linux distro
# (c) Roman Zhukov <roman@jadeite.su>, 2014
# Works on: CentOS 6.5, Oracle Linux 6.5, Debian 7, Ubuntu 14.04
# Warning: before run it on CentOS or Oracle, pease add EPEL and Remi's repo

SERVERNAME="testserv"
SERVERPATH="/var/www/$SERVERNAME"
subst="/usr/bin/perl -p -i -e"

[ -e /etc/issue ] || exit 1
DISTR=`head -n1 /etc/issue | awk '{print $1;}'`
[ -z $DISTR ] && exit 1

if [[ $DISTR == 'CentOS' ]] || [[ $DISTR == 'Oracle' ]]; then
    yum --enablerepo=remi,remi-php55 -y install nginx php-fpm php-common
    PHPFIXPATH=/etc/php.ini
    mkdir /etc/nginx/sites-available
    mkdir /etc/nginx/sites-enabled
    mv /etc/nginx/conf.d/* /etc/nginx/sites-available/
    $subst "s/^worker_processes.*/worker_processes  4;/g" /etc/nginx/nginx.conf
    $subst "s/include \/etc\/nginx\/sites-enabled\/\*;//g" /etc/nginx/nginx.conf
    $subst "s/(include \/etc\/nginx\/conf\.d\/\*\.conf;)/\1\n    include \/etc\/nginx\/sites-enabled\/\*;/g" /etc/nginx/nginx.conf
    PHPFPM="php-fpm"
    NGINX="nginx"
    chkconfig php-fpm on
    chkconfig nginx on
fi

if [[ $DISTR == 'Ubuntu' ]] || [[ $DISTR == 'Debian' ]]; then
   apt-get install -y nginx php5 php5-fpm
   PHPFIXPATH=/etc/php5/fpm/php.ini
   rm -f /etc/nginx/sites-enabled/*
   PHPFPM="php5-fpm"
   NGINX="nginx"
   $subst "s/^listen =.*/listen = 127.0.0.1:9000/g" /etc/php5/fpm/pool.d/www.conf
fi

$subst "s/.*cgi\.fix_pathinfo=.*/cgi\.fix_pathinfo = 0;/g" $PHPFIXPATH
mkdir -p $SERVERPATH
cat > /etc/nginx/sites-available/$SERVERNAME <<EOF
server {
    listen       80;
    server_name  $SERVERNAME;

    access_log  /var/log/nginx/$SERVERNAME.access.log;
    error_log   /var/log/nginx/$SERVERNAME.error.log;
    root   $SERVERPATH;
    index  index.html index.htm;

    location / {
        #try_files \$uri \$uri/ /index.html;
        index index.html index.htm index.php;
    }

    error_page  404              /404.html;
    location = /404.html {
        root   /usr/share/nginx/html;
    }
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
    location ~ \.php$ {
        root           html;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass   127.0.0.1:9000;
        fastcgi_index  index.php;
        include        fastcgi_params;
        fastcgi_param  SCRIPT_FILENAME  $SERVERPATH\$fastcgi_script_name;
    }
    location ~ /\.ht {
        deny  all;
    }
}
EOF

cat > $SERVERPATH/index.php <<EOF
<?php
phpinfo();
?>
EOF
ln -s /etc/nginx/sites-available/$SERVERNAME /etc/nginx/sites-enabled/
service $PHPFPM restart
service $NGINX restart
