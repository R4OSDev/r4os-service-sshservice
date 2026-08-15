SSHD.R4X
========

SSHD.R4X ist der SSH-Serverdienst fuer R4OS.

Seit 0.60.20 beantwortet SSHD `R4DIAG PING` und `R4DIAG TASKS` direkt im
Session-Worker. Dieser Diagnosepfad startet weder `TERMINAL.R4X` noch ein
anderes Programm und fuehrt kein Dateisystem-I/O aus. `TASKS` liefert den
generationstreuen Program-/Task-Snapshot mit Taskzustand, Owner, letztem
Lauf-Tick, Alter, Wake-Tick und Laufzeit; parallele Inventarmutationen
starten den Snapshot begrenzt neu. Alle Taskseiten werden dabei vor der
ersten SSH-Ausgabe in einem pro Session eigenen Scratchpuffer gesammelt:
Ein TCPSVC-Write erzeugt selbst einen kurzlebigen Async-I/O-Task und wuerde
einen noch laufenden generationstreuen Snapshot sonst invalidieren. Erst
der vollstaendige stabile Snapshot wird ueber SSH ausgegeben. Damit bleibt
bei einem SYSUPD-/Storage-Wedge ueber denselben SSH-Kanal unterscheidbar, ob
bereits der Session-Worker steht oder erst Spawn, Terminal beziehungsweise
Dateisystem nicht mehr fortschreiten.

SFTP-Schreibvertrag 0.60.20
---------------------------

SFTP-Uploads sind jetzt gestreamte, create-only Transaktionen. Ein Write-Open
akzeptiert nur den sequenziellen Create+Truncate-Vertrag und lehnt ein bereits
vorhandenes Ziel sichtbar ab; ein bestehendes Paket wird nicht mehr direkt
ueberschrieben. Jeder angenommene Upload bekommt eigene 8.3-kompatible
Stage-/Backupnamen im Zielverzeichnis. SSHD schreibt ausschliesslich in diese
eindeutige Stage-Datei und veroeffentlicht sie beim Close mit dem atomaren
R4SYS-Ownership-Transfer
`file_replace_atomic_flag_consume_stage|
file_replace_atomic_flag_require_target_absent|
file_replace_atomic_flag_require_owned_stage`.

SSHD ruft den Publish genau einmal auf und trifft danach keine
pfadbeobachtete Retry-/Delete-Entscheidung. R4SYS verlangt stattdessen einen
fertigen Streamslot desselben Prozesses samt Programmgeneration und bindet
ihn an die konkrete Stage-Identitaet und Groesse. Die atomare
Create-if-absent-Operation und eine eventuell noetige Reconciliation nach
verlorener Backend-Completion laufen unter demselben Filesystem-Gate. Nur
wenn R4SYS dort beweist, dass Ziel, Stage und Ownership zu genau diesem
Publish gehoeren, darf es Erfolg melden oder den Backendschritt intern
einmal fortsetzen. Ein nur gleichnamiges Ziel kann nie als eigener Upload
gelten.

Bei Write-, Finish-, Publish- oder Client-Abbruch ist `fileStreamAbort` die
einzige Cleanup-Autoritaet. Vor Publish darf es nur die exakt besessene Stage
entfernen. Nach einem mehrdeutigen begonnenen Publish gibt es den
In-Memory-Slot frei, loescht aber keinen Namen blind; ein privater Alias darf
zur Diagnose beziehungsweise spaeteren Recovery erhalten bleiben.
Primaerfehler und Cleanup-/Abort-Rueckgabe werden getrennt gemeldet.
`SERVMAN STATUS SSHD` haelt ausserdem die letzte abgeschlossene
SFTP-Schreibtelemetrie separat und sequenzgebunden fest
(`write_xfer_*`). Ein spaeterer Download oder die Aggregation eines aelteren
Worker-Slots darf Bytes, Ticks, Ergebnis, Pfad, Publish-RC und Cleanup-RC
dieses Uploads nicht ueberschreiben.

Das ist der implementierte Vertrag fuer die erneute Abnahme; er behauptet
noch keinen erfolgreichen Lenovo-Grossupload.

Seit 0.58.26 waermt SSHD hoechstens vier grosse Session-Scratch-Saetze vor.
Die acht Worker-Slots bleiben nutzbar, weitere Puffer werden aber erst bei
Bedarf allokiert. Damit kann ein frisches `MaxSessions=8` den Mainloop bei
knappem App-Heap nicht mehr durch dauernde fehlgeschlagene Vorallokationen
blockieren; Accept- und Service-Endpoint-Arbeit bleiben reaktionsfaehig.

Stand 0.55.9:

- Service-Name: `SSHD`
- Zielpfad im Image: `C:\R4OS\SERVICES\SSHD.R4X`
- Standard-Port: `22`
- QEMU-Standardweiterleitung: Host `127.0.0.1:10022` -> R4OS `10.0.2.15:22`
- Registry-Pfad: `SYSTEM\Services\SSHD`
- Standard-Zugangsdaten: `r4os` / `rosebud`

0.52.9 baut auf der dauerhaften Dienst- und Netzwerkbasis von 0.52.4 sowie
dem echten Transport aus 0.52.5 auf. Der Dienst lauscht ueber `TCPSVC` auf
Port 22, spricht mit Windows OpenSSH `curve25519-sha256`, `ssh-ed25519`,
`chacha20-poly1305@openssh.com` und `none`-Compression, authentifiziert
`r4os:rosebud` per SSH-Passwortauth und startet danach eine headless
Terminal-Sitzung, ein einzelnes Remote-Kommando, das SFTP-Subsystem oder
einfache klassische SCP-Transfers.

Der Ed25519-Host-Key wird beim ersten Start erzeugt und als
`HostKeySeed`/`HostKeyPublic` unter `SYSTEM\Services\SSHD` gespeichert.

Die Shell wird aus `ShellPath`/`ShellArgs` gelesen. Standard ist
`C:\R4OS\SOFTWARE\TERMINAL\TERMINAL.R4X /NOAUTOEXEC`; es wird kein sichtbares
Terminalfenster geoeffnet. SSHD verbindet den SSH-Channel ueber die
R4SYS-/Console-Host-APIs mit der normalen Terminal-Anwendung.

Seit 0.52.7 verarbeitet SSHD auch SSH-Exec-Requests. Ein Remote-Kommando wird
als `TERMINAL.R4X /NOAUTOEXEC /C <Befehl>` in einem headless Console-Host
gestartet. Die Ausgabe laeuft ueber den normalen Console-Output-Puffer zurueck
zum SSH-Channel; am Ende sendet SSHD `exit-status`, EOF und Close. Erfolgreiche
Befehle liefern Exitstatus `0`, unbekannte Terminal-Befehle liefern den
Terminal-Errorlevel, z.B. `1`.

SSHD haelt pro Verbindung weiterhin genau einen Session-Channel aktiv.
Window-Adjust-Pakete werden gezaehlt und zweite Channel-Open-Versuche werden
kontrolliert abgewiesen. Beim Schliessen einer Shell- oder Exec-Sitzung wird
die Console-Ausgabe gezielt ausgedraint. Waehrenddessen bedient SSHD weiter
seinen Service-Endpoint, damit ein Remote-Befehl wie `SERVMAN STATUS SSHD`
auch dann vollstaendige Endpoint-Diagnose liefert, wenn er gerade dieselbe
SSHD-Instanz abfragt.

Seit 0.52.8 verarbeitet SSHD ausserdem das Subsystem `sftp`. Unterstuetzt ist
ein kleiner SFTP-v3-Umfang fuer Windows OpenSSH: Init/Version, Open, Close,
Read, Write, Stat/LStat/FStat, RealPath, OpenDir/ReadDir, MkDir sowie
SetStat/FSetStat als akzeptierter No-op. `/C/` wird auf `C:\` und `/D/` auf
`D:\` abgebildet; DOS-Pfade wie `C:\TEMP\DATEI.TXT` werden tolerant
angenommen. Der damalige 64-KB-Puffer-/Close-Write-Pfad wurde spaeter durch
den gestreamten Vertrag ersetzt. Verzeichnislisten nutzen die normale
R4SYS-Directory-Iteration und geben mehrere echte Eintraege pro
SFTP-Name-Antwort zurueck.

Seit 0.52.9 erkennt SSHD klassische OpenSSH-SCP-Exec-Kommandos im selben
Session-Channel. Unterstuetzt sind einfache Einzeldatei-Transfers mit
`scp -O`: Gast-zu-Host ueber `scp -f` und Host-zu-Gast ueber `scp -t`.
SCP nutzt dieselbe SSH-Session-, Channel- und Pfadlogik wie Exec/SFTP,
liest und schreibt ueber R4SYS, begrenzt Transfers aktuell auf 64 KB und
lehnt nicht unterstuetzte Optionen sichtbar ab, statt still auf einen zweiten
Kompatibilitaetspfad auszuweichen.

Seit 0.52.19 wartet die Passwortauthentifizierung mit einem eigenen
manuellen Auth-Timeout. Nach dem initialen OpenSSH-Auth-Versuch `none` und
nach falschen Passwoertern bleibt die Verbindung fuer weitere
Passwortversuche offen, statt nach einem kurzen Retry-Fenster zu schliessen.
Damit funktionieren menschlich getippte Logins in Windows Terminal und PuTTY
zuverlaessiger; schnelle AskPass-Tests bleiben weiterhin abgedeckt.
Ebenfalls seit 0.52.19 normalisiert SSHD fuer interaktive Shell-Kanaele
terminaltypische Enter-Sequenzen: `CR` und `CRLF` werden als genau ein `LF`
an die Console weitergereicht. SFTP und SCP bleiben bytegenau unveraendert.

`SERVMAN STATUS SSHD` zeigt neben dem Service-Status den Endpoint-Status des
Dienstes, unter anderem Sessions, Auth-Counter, letzten Login, fehlgeschlagene
Methode und bei `LogPasswords=ON` auch getestete Passwoerter. Auth-Versuche,
Fehler, Erfolge und gestartete Shells werden zusaetzlich an `LOGSVC`
geschrieben, wenn der Logdienst verfuegbar ist. Der Status zeigt ausserdem
Channel-Zaehler fuer Shells, Execs, Window-Adjusts sowie ein- und ausgehende
Channel-Datenbytes. Seit 0.52.8 gehoeren auch SFTP-Session-, Open-, Read-,
Write- und Readdir-Zaehler zur Diagnose. Seit 0.52.9 werden zusaetzlich
SCP-Sessions, SCP-Reads, SCP-Writes sowie SCP-Ein- und Ausgangsbytes
gezaehlt.

SFTP bleibt der bevorzugte moderne Dateiuebertragungsweg. SCP ist der
Kompatibilitaetspfad fuer bekannte Host-Werkzeuge und einfache Kopien.

Seit 0.53.16 nutzt der SSHD-Service-Endpoint den queue-basierten
R4SYS-Vertrag. `SERVMAN STATUS SSHD` und andere Status-Clients koennen damit
mehrere outstanding Endpoint-Requests absetzen, ohne auf den alten
Single-Slot-Vertrag zurueckzufallen. SSH-Session-Parallelitaet,
Dead-Connection-Erkennung und Transfer-Backpressure bleiben serviceeigene
Folgearbeit, nicht Kernel-Policy.

Seit 0.53.21 ist die neue R4NET-Socket-Completion ein Client-/SDK-Vertrag
ueber `TCPSVC`; SSHD bleibt bewusst auf demselben Servicepfad und bringt
keinen Kernel-SSH-, SFTP- oder SCP-Sonderpfad mit.

Stand 0.54.17: Die Liveanalyse erreicht SSHD ueber QEMU-Hostforwarding, aber
Windows OpenSSH bricht vor KEX ab. Die Endpoint-Diagnose zeigt
Worker-/Scratch-Probleme (`last=scratch`, Worker-Exit `-20`). Der folgende
Fix soll den Session-Scratch- und Worker-Lifecycle stabilisieren, ohne den
alten synchronen SSHD-Pfad oder einen Kernel-Sonderpfad als Fallback
zurueckzubringen.

Seit 0.54.18 gehoert der grosse Session-Scratch dem SSHD-Mainloop/Slot. Worker
bekommen einen vorbereiteten `SessionBuffers`-Zeiger, setzen ihn vor dem
Transport zurueck und allokieren/freigeben diese Puffer nicht mehr selbst.
`SERVMAN STATUS SSHD` zeigt dazu `scratch=<ready>/<in_use>`, `scratch_alloc`
und `scratch_fail`. Der OpenSSH-Transport erreicht wieder KEXINIT, NEWKEYS,
Service-Accept und die erwartete Auth-Ablehnung ohne Kernel-SSH- oder
Synchron-Fallback.

Seit 0.54.19 sind die Host-Testwerkzeuge auf diesen Vertrag nachgezogen:
Banner-Abnahmen erwarten keinen alten festen SSHD-Versionsstring mehr,
SSH-/SFTP-/SCP-Tests warten auf `Endpoint: SSHD OK port=22` und Fehlertexte
enthalten den letzten Endpoint-Snapshot sowie Marker fuer Transport,
Worker/Scratch, Task-/Module-Allocation und Crashpfade. Die direkten
OpenSSH-Aufrufe fuer manuelle Hosttests stehen in
`Docs/Network/SshHostTests05419.txt`.

Seit 0.54.20 ist die volle SSH-/SFTP-/SCP-Kette wieder live abgenommen. Der
Statuspfad bildet aktive Worker ueber einen Snapshot ab, sodass laufende
Sessions ihre Auth-, Shell-/Exec-, SFTP-/SCP- und Byte-Zaehler sichtbar
machen. Shell-/Exec-Sessions drainen Console-Ausgabe vor Exitstatus, EOF und
Channel-Close mit einem kurzen Flush-Fenster, damit groessere Remote-Exec-
Ausgaben wie `SERVMAN STATUS SSHD` vollstaendig beim OpenSSH-Client ankommen.
SFTP und SCP bleiben Userland-Pfade mit 64-KB-Transferpuffer; groessere
produktive Transfers brauchen spaeter Streaming und Backpressure statt einer
stillen Limit-Erhoehung.

Seit 0.55.8 ist SSHD als dauerhafter Administrationspfad fuer Windows OpenSSH
stabilisiert. `SERVMAN STATUS SSHD` meldet zusaetzlich EOF, Client-Close,
Client-Abbruch, Idle-Timeout, Output-Fehler, letzten Remote-Exitstatus, letzte
Sessionart, Abschlussgrund und letztes Exec-Kommando. Der Close-Drain wertet
kurzzeitige Output-Pump-Fehler nicht mehr als stabile Ausgabe; dadurch werden
lange Exec-Ausgaben vor Exitstatus/EOF/Close vollstaendig nachgereicht oder
der echte Client-Disconnect sichtbar gezaehlt.

Wenn ein Host-Client waehrend eines laufenden Remote-Programms verschwindet,
zaehlt SSHD `client_abort`, beendet das Remote-Programm, gibt die Session frei
und bleibt anschliessend per SSH-Exec erreichbar. Die reproduzierbare Abnahme
liegt in `Tests/Runtime/Run-SshAdminLiveTest0558.ps1`: Fast-
Exec, langer `TYPE`-Output, interaktive Shell mit `SERVMAN STATUS SSHD`,
hart beendetes `PAUSE` und Reconnect. SSHD bleibt dabei ein Userland-Service
ueber `TCPSVC`; SSH-Protokoll, Login-Policy und Session-Lifecycle wandern
nicht in den Kernel.

Seit 0.55.9 ist der Dateiuebertragungspfad fuer Windows OpenSSH deutlich
belastbarer: SFTP und klassisches `scp -O` schreiben Uploads gestreamt ueber
R4SYS-Dateistreams, zaehlen Transferbytes und melden letzten Transferpfad,
Transferart, Ergebnis und Abbruchpfade im SSHD-Status. SFTP unterstuetzt nun
auch Rename/Delete sowie den Update-Inbox-Pfad
`C:\R4OS\UPDATE\INBOX`; direkte Schreibversuche in geschuetzte Systempfade
wie `C:\R4OS\CONFIG`, `C:\BOOT` oder `C:\LIMINE` werden sichtbar
abgewiesen. SCP oeffnet den R4SYS-Dateistream erst beim ersten Nutzdatenblock,
damit ein Client-Abbruch direkt nach dem Dateikopf keinen haengenden Stream
hinterlaesst. Header-only- und Nutzdaten-Abbrueche werden als aktive
Transfer-Sessions ueberwacht, gezaehlt und geben den Dienst danach wieder fuer
Reconnects frei. Details und Logpfade stehen in
`Docs/Network/SshFileTransfer0559.txt`.

Nachhaertung 0.55.11: Fuer kernelgrosse Updatepakete nach
`C:\R4OS\UPDATE\INBOX` bleiben die Transfer-Waechter bei aktiver
Dateistreamarbeit laenger offen. Der innere SFTP-/SCP-Schreibloop meldet
Fortschritt vor und nach jedem R4SYS-Write, trifft aber keine harte
TCP-Poll-Abbruchentscheidung waehrend FAT32 gerade schreibt. Ein echter
Disconnect wird danach ueber den naechsten Paket- oder Antwortpfad sichtbar,
ohne den lokalen Stream unnoetig mitten im Dateisystem-Write zu zerreissen.
SSHD schreibt dabei bis zu 32 KB pro R4SYS-Stream-Chunk, passend zum
SSH-Channel-Paketlimit, damit grosse `.R4U`-Uploads nicht in tausende
kleine FAT32-Append-Operationen zerfallen.

Nachhaertung 0.55.39: Interaktive Shell-Sessions pumpen Console-/Serviceausgabe
auch waehrend SSHD auf das naechste verschluesselte Channel-Paket wartet.
Dadurch bleibt eine Sitzung nach langen Ausgaben, Scroll und nach parallelen
RDP-Abbruechen bedienbar. Der Koexistenztest
`Run-RdpSshCoexistence05539.ps1` prueft SSH vor und nach drei synthetischen
mstsc-modern-Abbruechen gegen RDPSVC.

Nachhaertung 0.55.39b: Auch der PreAuth-/KEX-Pfad nutzt jetzt kurz getaktete
TCPSVC-Servicepolls fuer Client-Ident und Plain-Packets. Kurzzeitige
Service-Timeouts oder TCPSVC-Antworten ohne gueltigen Handle werden bis zur
Sessionfrist als transient behandelt, statt einen echten Host-OpenSSH-Client
direkt nach `SSH_MSG_KEXINIT` zu trennen. Banner, Plain-KEX und
verschluesselte Pakete warten auf ein robust gepolltes TX-Fenster; echte
Write-Chunks werden nicht blind wiederholt, damit spaete TCPSVC-Antworten
keine doppelten SSH-Pakete erzeugen. `SERVMAN STATUS SSHD` meldet dafuer
`read_retry`, `write_retry`, `svc_retry`, `tcp_flags`, `tcp_status` und
`tcp_result`.
