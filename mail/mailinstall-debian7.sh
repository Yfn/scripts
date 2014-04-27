#!/bin/bash
# (c) Roman Zhukov 2010-2013
# This script install complete mail system (Postfix + Dovecot + amavis + spamassasin) 
# with virtual accounts stored in Postgresql database. Works on Debian 7 and Ubuntu 12.04

ORGANIZATION="RC Online"
domain='rc-online.org'
CREATE_DB="yes"

SUBST="/usr/bin/perl -p -i -e"
HOSTNAME="mail.$domain"
MAIL_GID=`id -g mail`

#. /etc/sysconfig/firewall/common
INTRA_NET="192.168.58.0/24"

hostname $HOSTNAME

aptitude install -y postfix postfix-pgsql postfix-cdb libsasl2-2 libsasl2-modules libsasl2-modules-sql libsasl2-modules-ldap sasl2-bin \
dovecot-antispam dovecot-common dovecot-core dovecot-imapd dovecot-pgsql dovecot-pop3d dovecot-ldap dovecot-sieve dovecot-managesieved \
amavisd-new amavis clamav clamav-daemon clamav-freshclam spamassassin postgrey fetchmail fetchmail-ssl postgresql python-psycopg2 \
libnet-dns-perl libmail-spf-perl pyzor razor arj bzip2 cabextract cpio file gzip nomarch pax rar unrar unzip zip zoo

# Installing PSQL mail database
if [ $CREATE_DB -eq "yes" ]; then
    dropdb -U postgres mail
    dropuser -U postgres mailadm
    dropuser -U postgres postfix
    createdb -U postgres mail
    createuser -U postgres -S -D -R mailadm
    createuser -U postgres -S -D -R postfix
    psql -U postgres mail < ./mail_schema.sql
    psql -U mailadm mail -c "insert into transport values('$domain','virtual',1,10);"
    cp -f ./mailadm /usr/local/sbin/
fi

# Creating mail directory
[ -d /var/mail/$domain ] || mkdir /var/mail/$domain
chown root:mail /var/mail/$domain
chmod 2777 /var/mail/$domain
chown root:postfix -R /etc/postfix/sasl
chmod 640 /etc/postfix/sasl/smtpd.conf

# Configuring Dovecot POP3/IMAP4 server
[ -d /etc/dovecot/conf.d.orig ] || mv /etc/dovecot/conf.d /etc/dovecot/conf.d.orig
mkdir /etc/dovecot/conf.d
[ -d /etc/dovecot/auth.d ] || mkdir /etc/dovecot/auth.d

echo "auth_username_chars = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@
auth_debug = yes
auth_mechanisms = plain login
service auth {
  unix_listener /var/spool/postfix/private/dovecot-auth {
    group = postfix
    mode = 0660
    user = postfix
  }
  user = root
}

" > /etc/dovecot/auth.d/10-dovecot-postfix.auth

echo "# Some general options
protocols = imap pop3 sieve
userdb {
  driver = passwd
}
userdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
protocol imap {
  imap_client_workarounds = delay-newmail
  mail_max_userip_connections = 10
}
protocol pop3 {
  mail_max_userip_connections = 10
  pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
  pop3_uidl_format = %08Xu%08Xv
}
protocol lda {
  auth_socket_path = /var/run/dovecot-auth-master
  deliver_log_format = msgid=%m: %$
  log_path = /var/log/dovecot-local-deliver.log
  mail_plugins = sieve
  postmaster_address = postmaster
  quota_full_tempfail = yes
  rejection_reason = Your message to <%t> was automatically rejected:%n%r
}
" > /etc/dovecot/conf.d/10-dovecot-postfix.conf
echo "ssl = yes
ssl_cert = </etc/ssl/certs/dovecot.pem
ssl_cipher_list = ALL:!LOW:!SSLv2:ALL:!aNULL:!ADH:!eNULL:!EXP:RC4+RSA:+HIGH:+MEDIUM
ssl_key = </etc/ssl/private/dovecot.pem
" > /etc/dovecot/conf.d/10-ssl.conf

[ -e /etc/dovecot/dovecot.conf.orig ] || mv /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig
echo "base_dir = /var/run/dovecot
log_timestamp = %Y-%m-%d %H:%M:%S
mail_debug = yes
mail_location = maildir:/var/mail/%d/%n
mail_privileged_group = mail
managesieve_notify_capability = mailto
managesieve_sieve_capability = fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date ihave
passdb {
  driver = pam
}
passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
plugin {
  sieve = /var/opt/sieve_scripts/%u.sieve
  sieve_global_path = /var/opt/sieve_scripts/global.dovecot.sieve
}
!include_try /etc/dovecot/auth.d/*.auth
!include_try /etc/dovecot/conf.d/*.conf
" > /etc/dovecot/dovecot.conf

[ -e /etc/dovecot/dovecot-sql.conf.orig ] || mv /etc/dovecot/dovecot-sql.conf /etc/dovecot/dovecot-sql.conf.orig
echo "driver = pgsql
connect = host=localhost dbname=mail user=mailadm password=postfix
default_pass_scheme = PLAIN
password_query = SELECT email as user, passwd as password FROM users WHERE email='%u'
user_query = SELECT maildir as home, uid, gid FROM users WHERE email='%u'
" > /etc/dovecot/dovecot-sql.conf

# Configuring Postfix MTA
# Step 1: Configuring SASL
echo 'pwcheck_method: auxprop' > /etc/postfix/sasl/smtpd.conf
echo 'mech_list: plain login' >> /etc/postfix/sasl/smtpd.conf
echo 'auxprop_plugin: sql' >> /etc/postfix/sasl/smtpd.conf
echo 'sql_engine: pgsql' >> /etc/postfix/sasl/smtpd.conf
echo 'sql_user: mailadm' >> /etc/postfix/sasl/smtpd.conf
echo 'sql_passwd: 10ZFm5ulQj17rcdI' >> /etc/postfix/sasl/smtpd.conf
echo 'sql_hostnames: 127.0.0.1' >> /etc/postfix/sasl/smtpd.conf
echo 'sql_database: mail' >> /etc/postfix/sasl/smtpd.conf
echo "sql_select: select passwd from users where email='%u@%r' and enabled=1" >> /etc/postfix/sasl/smtpd.conf
echo 'sql_verbose: yes' >> /etc/postfix/sasl/smtpd.conf
$SUBST "s/^START=.*$/START=yes/g" /etc/default/saslauthd
# Step 1.1: Configuring PGSQL
mkdir -p /etc/postfix/pgsql
echo 'user = postfix
password = gm8qhb2eBXVMCYmA
dbname = mail
query = SELECT domain FROM transport WHERE domain='%s'
hosts = 127.0.0.1' > /etc/postfix/pgsql/pgsql-mydestination.cf
echo 'user = postfix
password = gm8qhb2eBXVMCYmA
dbname = mail
query = SELECT transport FROM transport WHERE domain='%s'
hosts = 127.0.0.1' > /etc/postfix/pgsql/pgsql-transport.cf
echo 'user = postfix
password = gm8qhb2eBXVMCYmA
dbname = mail
query = SELECT gid FROM users WHERE email='%s' AND enabled=1
hosts = 127.0.0.1' > /etc/postfix/pgsql/pgsql-virtual-gid.cf
echo 'user = postfix
password = gm8qhb2eBXVMCYmA
dbname = mail
query = SELECT maildir FROM users WHERE email='%s' AND enabled = 1
hosts = 127.0.0.1' > /etc/postfix/pgsql/pgsql-virtual-maps.cf
echo 'user = postfix
password = gm8qhb2eBXVMCYmA
dbname = mail
additional_conditions = and enabled = 1
query = SELECT uid FROM users WHERE email='%s' AND enabled=1
hosts = 127.0.0.1' > /etc/postfix/pgsql/pgsql-virtual-uid.cf
echo 'user = postfix
password = gm8qhb2eBXVMCYmA
dbname = mail
query = SELECT goto FROM alias WHERE address='%s'
hosts = 127.0.0.1' > /etc/postfix/pgsql/pgsql-virtual.cf

# Step 2: Creating SSL Certificates
rm -f /etc/postfix/*.pem
rm -f /etc/postfix/*.rand
rm -f /etc/postfix/*.key
rm -f /etc/postfix/*.cert

echo "RANDFILE = /etc/postfix/postfix.rand

[ req ]
default_bits = 2048
encrypt_key = yes
distinguished_name = req_dn
x509_extensions = cert_type
prompt = no

[ req_dn ]
C=RU
ST=Ural
L=Yekaterinburg
O=$ORGANIZATION
OU=Automatically-generated SMTP SSL certificate
CN=$HOSTNAME
emailAddress=postmaster@$domain

[ cert_type ]
nsCertType = server
" > /etc/postfix/postfix.cnf

echo "RANDFILE = /etc/postfix/imapd.rand
[ req ]
default_bits = 1024
encrypt_key = yes
distinguished_name = req_dn
x509_extensions = cert_type
prompt = no

[ req_dn ]
C=RU
L=Net
O=Courier Mail Server
OU=Automatically-generated IMAP SSL key
CN=$HOSTNAME
emailAddress=postmaster@$domain


[ cert_type ]
nsCertType = server
" > /etc/postfix/imapd.cnf

echo "RANDFILE = /etc/postfix/pop3d.rand

[ req ]
default_bits = 1024
encrypt_key = yes
distinguished_name = req_dn
x509_extensions = cert_type
prompt = no

[ req_dn ]
C=RU
L=Net
O=Dovecot Mail Server
OU=Automatically-generated POP3 SSL key
CN=$HOSTNAME
emailAddress=postmaster@$domain


[ cert_type ]
nsCertType = server
" > /etc/postfix/pop3d.cnf

dd if=/dev/urandom of=/etc/postfix/postfix.rand count=1 2>/dev/null
dd if=/dev/urandom of=/etc/postfix/imapd.rand count=1 2>/dev/null
dd if=/dev/urandom of=/etc/postfix/pop3d.rand count=1 2>/dev/null

openssl req -new -config /etc/postfix/postfix.cnf -outform PEM -out /etc/postfix/smtpd.cert -newkey rsa:2048 -nodes -keyout /etc/postfix/smtpd.key -keyform PEM -days 720 -x509
#openssl req -new -x509 -days 720 -nodes -config /etc/postfix/imapd.cnf -out /etc/courier/imapd.pem -keyout /etc/courier/imapd.pem
#openssl gendh -rand /etc/postfix/imapd.rand 512 >>/etc/courier/imapd.pem
#openssl x509 -subject -dates -fingerprint -noout -in /etc/courier/imapd.pem
#openssl req -new -x509 -days 720 -nodes -config /etc/postfix/pop3d.cnf -out /etc/courier/pop3d.pem -keyout /etc/courier/pop3d.pem
#openssl gendh -rand /etc/postfix/pop3d.rand 512 >>/etc/courier/pop3d.pem
#openssl x509 -subject -dates -fingerprint -noout -in /etc/courier/pop3d.pem
rm -f /etc/postfix/*.rand
rm -f /etc/postfix/*.cnf

# Step 3: Creating main postfix configuration
touch /etc/postfix/main.cf
postconf -e "myhostname = mail.$domain"
postconf -e "mydomain = $domain"
postconf -e 'myorigin = $myhostname'
postconf -e 'inet_interfaces = all'
postconf -e 'mydestination = localhost, $myhostname, localhost.$mydomain, $config_directory/mydestination, pgsql:/etc/postfix/pgsql/pgsql-mydestination.cf'
postconf -e 'local_recipient_maps = $alias_maps $virtual_mailbox_maps'
postconf -e 'unknown_local_recipient_reject_code = 550'
postconf -e 'access_map_reject_code = 550'
postconf -e 'mynetworks = $config_directory/mynetworks'
postconf -e 'mail_spool_directory = /var/mail'
postconf -e 'smtpd_banner = $myhostname ESMTP'
postconf -e 'smtpd_etrn_restrictions = permit_mynetworks, reject'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'content_filter = smtp-amavis:[127.0.0.1]:10024'
postconf -e 'broken_sasl_auth_clients = yes'
postconf -e 'smtpd_sasl_authenticated_header = yes'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, check_policy_service inet:127.0.0.1:60000'
postconf -e 'smtpd_sasl_security_options = noanonymous'
postconf -e 'smtpd_sasl_local_domain = $myhostname'
postconf -e 'smtpd_use_tls = yes'
postconf -e 'smtpd_tls_cert_file = /etc/postfix/smtpd.cert'
postconf -e 'smtpd_tls_key_file = /etc/postfix/smtpd.key'
postconf -e 'virtual_mailbox_base = /'
postconf -e 'virtual_mailbox_maps = pgsql:/etc/postfix/pgsql/pgsql-virtual-maps.cf'
postconf -e 'virtual_maps =  pgsql:/etc/postfix/pgsql/pgsql-virtual.cf'
postconf -e 'virtual_minimum_uid = 1000'
postconf -e 'virtual_uid_maps = pgsql:/etc/postfix/pgsql/pgsql-virtual-uid.cf'
postconf -e 'virtual_gid_maps = pgsql:/etc/postfix/pgsql/pgsql-virtual-gid.cf'
postconf -e 'transport_maps = pgsql:/etc/postfix/pgsql/pgsql-transport.cf'
postconf -e 'default_destination_concurrency_limit = 20'
postconf -e 'default_destination_recipient_limit = 50'
postconf -e 'initial_destination_concurrency = 2'
postconf -e 'maximal_queue_lifetime = 5d'
postconf -e 'minimal_backoff_time = 1000s'
postconf -e 'queue_run_delay = 1000s'
postconf -e 'message_size_limit = 102400000'
postconf -e 'virtual_mailbox_limit = 102400000'
postconf -e 'mailbox_size_limit = 102400000'
postconf -e 'mailbox_command = /usr/bin/procmail -a $DOMAIN -d $LOGNAME'
postconf -e 'smtpd_delay_reject = yes'
postconf -e 'smtpd_helo_required = yes'
echo "smtpd_helo_restrictions =
    permit_mynetworks,
    check_helo_access
	hash:/etc/postfix/helo_access,
    reject_non_fqdn_hostname,
    reject_invalid_hostname,
    reject_rbl_client bl.spamcop.net,
    reject_rbl_client sbl-xbl.spamhaus.org,
    reject_rbl_client dnsbl.njabl.org,
    reject_rbl_client dnsbl.sorbs.net,
    reject_rhsbl_client rhsbl.sorbs.net,
    permit" >> /etc/postfix/main.cf

postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/dovecot-auth'
postconf -e 'smtpd_sender_restrictions = reject_unknown_sender_domain'
postconf -e 'smtp_use_tls = yes'
postconf -e 'smtpd_tls_received_header = yes'
postconf -e 'smtpd_tls_mandatory_protocols = SSLv3, TLSv1'
postconf -e 'smtpd_tls_mandatory_ciphers = medium'
postconf -e 'smtpd_tls_auth_only = yes'
postconf -e 'tls_random_source = dev:/dev/urandom'
postconf -e 'mailbox_transport = dovecot'
postconf -e 'queue_directory = /var/spool/postfix'

echo "# Basic system aliases -- these MUST be present.
MAILER-DAEMON:  postmaster
postmaster:     root

### BEGIN aliases recommended by RFC 2142 ###

## Business-related mailbox names.
# Packaged information about the organization, products, and/or services, as appropriate
info:           postmaster
# Product marketing and marketing communications
marketing:      postmaster
# Product purchase information
sales:          postmaster
# Problems with product or service
support:        postmaster

## Network operations mailbox names.
# Inappropriate public behaviour
abuse:          postmaster
# Network infrastructure
oc:            postmaster
# Security bulletins or queries
security:       postmaster

### END aliases recommended by RFC 2142 ###

# Other well-known service aliases.
daemon:         postmaster
ftp:            postmaster
hostmaster:     postmaster
lp:             postmaster
mail:           postmaster
news:           postmaster
usenet:         news
uucp:           postmaster
webmaster:      postmaster
www:            webmaster

# Person who should get root's mail.
root:           rzhukov@rc-online.org

# Local system aliases" > /etc/postfix/aliases

echo 'smtp      inet  n       -       -       -       -       smtpd
pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
smtp-amavis unix -      -       n       -       2       smtp
    -o smtp_data_done_timeout=1200
127.0.0.1:10025 inet n  -       n       -       -       smtpd
    -o content_filter=
    -o local_recipient_maps=
    -o relay_recipient_maps=
    -o smtpd_restriction_classes=
    -o smtpd_client_restrictions=
    -o smtpd_helo_restrictions=
    -o smtpd_sender_restrictions=
    -o smtpd_recipient_restrictions=permit_mynetworks,reject
    -o mynetworks=127.0.0.0/8
    -o strict_rfc821_envelopes=yes
    -o smtpd_error_sleep_time=0
    -o smtpd_soft_error_limit=1001
    -o smtpd_hard_error_limit=1000
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
    -o smtp_fallback_relay=
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache
maildrop  unix  -       n       n       -       -       pipe
    flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
    flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
    flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
    flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix  -       n       n       -       2       pipe
    flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
    flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
    ${nexthop} ${user}

submission inet n       -       -       -       -       smtpd
    -o smtpd_tls_security_level=encrypt
    -o smtpd_sasl_auth_enable=yes
    -o smtpd_sasl_type=dovecot
    -o smtpd_sasl_path=private/dovecot-auth
    -o smtpd_sasl_security_options=noanonymous
    -o smtpd_sasl_local_domain=$myhostname
    -o smtpd_client_restrictions=permit_sasl_authenticated,reject
    -o smtpd_sender_login_maps=hash:/etc/postfix/virtual
    -o smtpd_sender_restrictions=reject_sender_login_mismatch
    -o smtpd_recipient_restrictions=reject_non_fqdn_recipient,reject_unknown_recipient_domain,permit_sasl_authenticated,reject
' > /etc/postfix/master.cf

touch /etc/postfix/transport
touch /etc/postfix/mydestination
echo "127.0.0.1/32" > /etc/postfix/mynetworks
echo $INTRA_NET >> /etc/postfix/mynetworks
echo "$domain\tOK" > /etc/postfix/helo_access
postmap /etc/postfix/helo_access
postmap cdb:/etc/postfix/transport
newaliases

# Configuring SpamAssassin
$SUBST "s/^ENABLED=.*$/ENABLED=1/g" /etc/default/spamassassin
echo "
required_hits 7

rewrite_header Subject [* SPAM? *]

report_safe 0

use_auto_whitelist 1
whitelist_from_rcvd *@$domain $domain
whitelist_from_rcvd *@rc-online.ru rc-online.ru
whitelist_from_rcvd *@rc-online.org rc-online.org

use_bayes 1
bayes_file_mode 0775
bayes_auto_learn 1
bayes_ignore_header X-Bogosity
bayes_ignore_header X-Spam-Flag
bayes_ignore_header X-Spam-Status
bayes_auto_learn_threshold_nonspam 1.
bayes_auto_learn_threshold_spam 14.00.

lock_method flock

use_pyzor 1

skip_rbl_checks 0

ok_locales all

clear_report_template
report Content analysis details on host _HOSTNAME_: _HITS_ points, _REQD_ required
report _SUMMARY_" > /etc/spamassassin/local.cf

# Configuring Amavis

$SUBST 's/^\$final_spam_destiny.*$/\$final_spam_destiny       = D_DISCARD;/g' /etc/amavis/conf.d/20-debian_defaults
echo "use strict;" > /etc/amavis/conf.d/05-node_id
echo 'chomp($myhostname = `hostname --fqdn`);' >> /etc/amavis/conf.d/05-node_id
echo -n '$myhostname = ' >> /etc/amavis/conf.d/05-node_id
echo "\"$HOSTNAME\";" >> /etc/amavis/conf.d/05-node_id
echo "1;  # ensure a defined return" >> /etc/amavis/conf.d/05-node_id
$SUBST 's/POSTGREY_OPTS=.*$/POSTGREY_OPTS="--inet=60000 --delay=150"/g' /etc/default/postgrey

chmod -R 775 /var/lib/amavis/tmp
adduser clamav amavis
adduser amavis clamav
adduser postfix sasl

# Gran Finale: Restarting all services
invoke-rc.d saslauthd restart
invoke-rc.d postgrey restart
invoke-rc.d spamassassin restart
invoke-rc.d clamav-daemon stop
freshclam
invoke-rc.d clamav-daemon start
invoke-rc.d amavis restart
invoke-rc.d dovecot restart
invoke-rc.d postfix restart
