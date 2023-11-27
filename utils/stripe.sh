#!/usr/bin/env bash

python manage.py djstripe_init_customers

python manage.py djstripe_sync_plans_from_stripe
