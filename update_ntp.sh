#! /bin/bash

NTP_SERVER="ntp.nict.jp"
LOG_FILE=/root/log/`basename $0 .sh`.log

update_ntp() {
  /usr/sbin/ntpdate ${NTP_SERVER}
}

update_ntp 2>&1 | tee -a ${LOG_FILE}

