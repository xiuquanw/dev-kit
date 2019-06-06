systemctl stop mysqld
systemctl set-environment MYSQLD_OPTS="--skip-grant-tables"
systemctl start mysqld
mysql -u root

mysql> use mysql; 
mysql> update user set authentication_string=password('you new pass') where user='root';
mysql> flush privileges; 
mysql> exit

systemctl restart mysqld