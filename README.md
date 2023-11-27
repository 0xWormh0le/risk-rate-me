Riskrate.me
===========

Riskrate.me is a Django-based project providing users with a scored asessement of the security of their public-facing IT infrastructure. 
It does so by looking a specific DNS records, mail servers, secure HTTP configuration, HTTP headers and cookies and online information about leaked credentials and malware.

Requirements
------------

* Ubuntu 18.04
* Nginx
* Python3
* Django >= 2.2
* Redis
* Gunicorn

Installation
------------

Connect to your Ubuntu server using SSH. Once logged in, first add the repository to install `certbot`, which is needed to use Let's Encrypt:

```shell
sudo add-apt-repository ppa:certbot/certbot
sudo apt update
```

Then proceed to the required packages:

```shell
sudo apt install -y python3-pip python3-dev python3-venv nginx curl redis-server mysql-server
```

Finish MySQL installation by securing it and setting root password:

```shell
mysql_secure_installation
```

Create a new database:

```shell
mysql
CREATE SCHEMA riskrateme;
exit
```

Copy database config file and change the db password there to the real one:

```shell
sudo cp ./utils/my.cnf my.cnf
```

Clone the project to the home directory of a non-root user:

```shell
git clone https://www.bitbucket.org/deepcodeinc/riskrate.me
```

Then create the virtual environment for Python and activate it;

```shell
python3 -m venv ./venv
source ./venv/bin/activate
```

We are now ready to install the Python module required for the project:

```shell
sudo -H pip install --upgrade pip
sudo -H pip install wheel
sudo -H pip install -r requirements.txt
```

Because this is a Django project, we initialize the database and project:

```shell
python manage.py makemigrations
python manage.py migrate
python manage.py djstripe_init_customers
python manage.py djstripe_sync_plans_from_stripe
python manage.py createsuperuser
python manage.py collectstatic
```

Load additional data related to sectors/tests:

```shell
python manage.py loaddata data/sectors.json
python manage.py loaddata data/testdefinitions.json
```

We use `Gunicorn` as the WSGI server for the project. The server can be setup using the following commands:

```shell
sudo cp ./utils/gunicorn.* /etc/systemd/system/
sudo systemctl start gunicorn.socket
sudo systemctl enable gunicorn.socket
```

We can then setup our `Nginx` server. If you are setting a development server, then use the following:

```shell
cp ./utils/dev.riskrate.me.nginx /etc/nginx/sites-available/dev.riskrate.me
ln -s /etc/nginx/sites-available/dev.riskrate.me.nginx /etc/nginx/sites-enabled
```

Otherwise, if you are setting up a production server, use the production configuration:

```shell
cp ./utils/www.riskrate.me.nginx /etc/nginx/sites-available/www.riskrate.me
ln -s /etc/nginx/sites-available/www.riskrate.me.nginx /etc/nginx/sites-enabled
```

And conclude the `Nginx` setup by rebooting the server:
```shell
nginx -t
sudo systemctl restart nginx
```

And ensure the `UFW` firewall allows HTTP traffic;
```shell
sudo ufw allow 'Nginx Full'
```

Setting Up Self-Signed Certificates
-----------------------------------

If setting up a development server, or another non-production server where self-signed certificates are good enough. This can be setup as follow:
```shell
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
openssl dhparam -out /etc/nginx/dhparam.pem 4096
sudo cp ./self-signed.conf /etc/nginx/snippets/
sudo cp ./self-params.conf /etc/nginx/snippets/
```

Setting Up Let's Encrypt
------------------------

For production servers, we use the `Let's Encrypt` service. Steps to setup this service can be found [here](https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-18-04). Remember to allow all HTTP traffic by disabling any restricting firewall 
rules when obtaining the certificates. 

Celery
------

The `celery` module is used to process scannigng requests and must be started separately from the project. First ensure that the `redis` server is started in the background:
```shell
sudo redis-server &
```

Then initiate the `celery` daemon:
```shell
celery -A riskrateme worker -l info --without-gossip --without-mingle --without-heartbeat -Ofair -P solo &
```
