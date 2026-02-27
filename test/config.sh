#!/bin/bash

#export SRCDIR=$(dirname $(cd ${0%/*} 2>>/dev/null ; echo `pwd`/${0##*/}))
export ROOT_DIR="${SRCDIR}/.."

export UNIFIED_CLIENT=${ROOT_DIR}/build/bin/client
export OLDSERVER_PORT=${OLDSERVER_PORT:=8444}
export NEWSERVER_PORT=${NEWSERVER_PORT:=8443}

export OLDSERVER_CURL_TLS_ARGS=${OLDSERVER_CURL_TLS_ARGS:="--tls-max 1.2"}
export NEWSERVER_CURL_TLS_ARGS=${NEWSERVER_CURL_TLS_ARGS:=""}

export OLDSERVER_CACERT=${OLDSERVER_CACERT:="${ROOT_DIR}/example/certs/server1/ca.crt"}
export OLDSERVER_CERT=${OLDSERVER_CERT:="${ROOT_DIR}/example/certs/server1/client.crt"}
export OLDSERVER_KEY=${OLDSERVER_KEY:="${ROOT_DIR}/example/certs/server1/client.key"}

export NEWSERVER_CACERT=${NEWSERVER_CACERT:="${ROOT_DIR}/example/certs/server2/ca.crt"}
export NEWSERVER_CERT=${NEWSERVER_CERT:="${ROOT_DIR}/example/certs/server2/client.crt"}
export NEWSERVER_KEY=${NEWSERVER_KEY:="${ROOT_DIR}/example/certs/server2/client.key"}

export OLDSERVER_USER=${OLDSERVER_USER:=""}
export OLDSERVER_PASS=${OLDSERVER_PASS:=""}
export NEWSERVER_USER=${NEWSERVER_USER:=""}
export NEWSERVER_PASS=${NEWSERVER_PASS:=""}

export OLDSERVER_PASSWORDS_FILE=${OLDSERVER_PASSWORDS_FILE:="${ROOT_DIR}/example/oldserver.users"}
export NEWSERVER_PASSWORDS_FILE=${NEWSERVER_PASSWORDS_FILE:="${ROOT_DIR}/example/newserver.users"}

if [ -z "${OLDSERVER_USER}" -o -z "${OLDSERVER_PASS}" ] ; then
  if [ -f "${OLDSERVER_PASSWORDS_FILE}" ] ; then
    first_line=$(grep -v "^[[:space:]]*$" "${OLDSERVER_PASSWORDS_FILE}" | grep -v "^[[:space:]]*#" | head -n 1)
    OLDSERVER_USER=${OLDSERVER_USER:=${first_line%%:*}}
    OLDSERVER_PASS=${OLDSERVER_PASS:=${first_line#*:}}
  fi
fi

if [ -z "${NEWSERVER_USER}" -o -z "${NEWSERVER_PASS}" ] ; then
  if [ -f "${NEWSERVER_PASSWORDS_FILE}" ] ; then
    first_line=$(grep -v "^[[:space:]]*$" "${NEWSERVER_PASSWORDS_FILE}" | grep -v "^[[:space:]]*#" | head -n 1)
    NEWSERVER_USER=${NEWSERVER_USER:=${first_line%%:*}}
    NEWSERVER_PASS=${NEWSERVER_PASS:=${first_line#*:}}
  fi
fi
