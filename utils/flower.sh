#!/usr/bin/env bash

pip install flower
celery flower -A riskrateme --broker=redis://localhost:6379
