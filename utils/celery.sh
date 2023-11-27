#!/usr/bin/env bash
#taskkill /IM celery.exe -F
celery -A riskrateme purge -f
celery -A riskrateme worker -l info --without-gossip --without-mingle --without-heartbeat -Ofair -P solo &