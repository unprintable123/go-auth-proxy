#!/bin/sh /etc/rc.common
START=95
STOP=10
SERVICE_NAME="luci_proxy"
PROG="/usr/bin/luci-proxy"

USE_PROCD=1

start_service() {
    procd_open_instance "$SERVICE_NAME"
    procd_set_param command "$PROG"
    procd_set_param respawn
    procd_close_instance
}

stop_service() {
    return 0
}
