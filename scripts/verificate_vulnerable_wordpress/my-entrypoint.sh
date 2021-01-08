#!/bin/bash

(crontab -l 2> /dev/null; echo "* * * * * /usr/local/bin/php /var/www/html/wp-cron.php") | crontab -
cron
/usr/local/bin/docker-entrypoint.sh "$@"
