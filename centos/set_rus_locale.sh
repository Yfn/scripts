#!/bin/sh

echo 'LANG="ru_RU.UTF-8"
LC_CTYPE="ru_RU.UTF-8"
SUPPORTED="ru_RU.UTF-8:ru_RU:ru"
SYSFONT="latarcyrheb-sun16"' >> /etc/sysconfig/i18n
localedef -v -c -i ru_RU -f UTF-8 ru_RU.UTF-8
exit

