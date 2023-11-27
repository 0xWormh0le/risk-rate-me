#!/usr/bin/env bash

add-apt-repository ppa:certbot/certbot
apt update
apt install python3-pip python3-dev python3-venv nginx curl redis-server
apt install python-certbot-nginx


python3 -m venv ./venv
source ./venv/bin/activate
pip install --upgrade pip
pip install wheel
pip install -r requirements.txt

python manage.py makemigrations
python manage.py migrate
python manage.py djstripe_init_customers
python manage.py djstripe_sync_plans_from_stripe
python manage.py createsuperuser
python manage.py collectstatic

#gunicorn --bind 0.0.0.0:8000 riskrateme.wsgi:application
cp ./utils/gunicorn.* /etc/systemd/system/
systemctl start gunicorn.socket
systemctl enable gunicorn.socket

cp ./utils/dev.riskrate.me.nginx /etc/nginx/sites-available/dev.riskrate.me
cp ./utils/www.riskrate.me.nginx /etc/nginx/sites-available/www.riskrate.me

ln -s /etc/nginx/sites-available/dev.riskrate.me /etc/nginx/sites-enabled
#ln -s /etc/nginx/sites-available/www.riskrate.me /etc/nginx/sites-enabled
nginx -t
systemctl restart nginx
ufw allow 'Nginx Full'

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
openssl dhparam -out /etc/nginx/dhparam.pem 4096
cp ./self-signed.conf /etc/nginx/snippets/
cp ./self-params.conf /etc/nginx/snippets/
