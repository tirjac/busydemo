#!/bin/bash
export SRCDIR=$(dirname $(cd ${0%/*} 2>>/dev/null ; echo `pwd`/${0##*/}))
. ${SRCDIR}/config.sh

## ---- variables
if [ -z ${OLDSERVER_PORT+x} ] ; then echo "OLDSERVER_PORT not set" ; exit 1 ; fi
if [ -z ${OLDSERVER_CACERT+x} ] ; then echo "OLDSERVER_CACERT not set" ; exit 1 ; fi
if [ -z ${OLDSERVER_CERT+x} ] ; then echo "OLDSERVER_CERT not set" ; exit 1 ; fi
if [ -z ${OLDSERVER_KEY+x} ] ; then echo "OLDSERVER_KEY not set" ; exit 1 ; fi
if [ -z ${OLDSERVER_USER+x} ] ; then echo "OLDSERVER_USER not set" ; exit 1 ; fi
if [ -z ${OLDSERVER_PASS+x} ] ; then echo "OLDSERVER_PASS not set" ; exit 1 ; fi
if [ -z ${UNIFIED_CLIENT+x} ] ; then echo "UNIFIED_CLIENT not set" ; exit 1 ; fi

## ---- main
${UNIFIED_CLIENT} localhost ${OLDSERVER_PORT} ${OLDSERVER_CACERT} ${OLDSERVER_CERT} ${OLDSERVER_KEY} ${OLDSERVER_USER} ${OLDSERVER_PASS} "/oldapi/setuser" "POST" "{\"nickname\":\"bob\",\"age\":29}"
