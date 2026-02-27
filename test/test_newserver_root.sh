#!/bin/bash
export SRCDIR=$(dirname $(cd ${0%/*} 2>>/dev/null ; echo `pwd`/${0##*/}))
. ${SRCDIR}/config.sh

## ---- variables
if [ -z ${NEWSERVER_PORT+x} ] ; then echo "NEWSERVER_PORT not set" ; exit 1 ; fi
if [ -z ${NEWSERVER_CACERT+x} ] ; then echo "NEWSERVER_CACERT not set" ; exit 1 ; fi
if [ -z ${NEWSERVER_CERT+x} ] ; then echo "NEWSERVER_CERT not set" ; exit 1 ; fi
if [ -z ${NEWSERVER_KEY+x} ] ; then echo "NEWSERVER_KEY not set" ; exit 1 ; fi
if [ -z ${NEWSERVER_USER+x} ] ; then echo "NEWSERVER_USER not set" ; exit 1 ; fi
if [ -z ${NEWSERVER_PASS+x} ] ; then echo "NEWSERVER_PASS not set" ; exit 1 ; fi
if [ -z ${UNIFIED_CLIENT+x} ] ; then echo "UNIFIED_CLIENT not set" ; exit 1 ; fi

## ---- main
${UNIFIED_CLIENT} localhost ${NEWSERVER_PORT} ${NEWSERVER_CACERT} ${NEWSERVER_CERT} ${NEWSERVER_KEY} ${NEWSERVER_USER} ${NEWSERVER_PASS} "/" "GET"
