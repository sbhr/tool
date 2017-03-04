#! /bin/bash

# update-mydns-shibahara.sh (v0.1.0, 2014-11-26)

USERNAME=""
PASSWORD=""
LOGIN_URL="http://www.mydns.jp/login.html"

LOG_FILE=/root/log/`basename $0 .sh`.log

update_mydns() {
  wget -q -O /dev/null --http-user=${USERNAME} --http-passwd=${PASSWORD} ${LOGIN_URL}
  if [ $? -eq 0 ]; then
    echo "`date`: update succeeded."
  else
    echo "`date`: update failed."
  fi
}

update_mydns 2>&1 | tee -a ${LOG_FILE}

