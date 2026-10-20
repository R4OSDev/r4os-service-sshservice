# SSHD.R4X

`SSHD.R4X` is an independent R4OS service implemented in Zig.

## Package

- Version: `0.1.17`
- Image target: `/R4OS/SERVICES/SSHD.R4X`
- Image scope: `full`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

When a console program exits, SSHD queues its final stable console revision
before sending exit status, EOF and close. Program completion between the
output and status queries can no longer discard the final lines. Backpressure
and unstable snapshots retain the channel for the next normal pump.

## Build

On Windows:

    Build.bat

On Linux or macOS:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.


Sitzungszufall und Hostidentitaet ab 0.78.61
-----------------------------------------
Ein frischer Hardware-Seed initialisiert pro SSH-Verbindung den ChaCha-CSPRNG
aus der mitgelieferten Zig-Standardbibliothek. Cookie, Padding und temporaerer
X25519-Wert werden daraus versorgt. Keine Host-ID-/Zeit-Ersatzquelle.
Fehlt die Quelle, endet der Handshake mit session-entropy-unavailable.
Lokale Seed-, RNG- und temporaere ECDH-Puffer werden nach Verwendung geleert.

Neue Ed25519-Hostschluessel erhalten einen eigenen Hardware-Seed. Seed,
Public-Key und HostKeyRngVersion (Binaerwert 01 00 00 00) werden gemeinsam
mit einer Registry-Batchaenderung publiziert. Ein vollstaendiges gueltiges
altes Paar ohne Markierung wird einmal ersetzt; PreviousHostKeyPublic
bewahrt ausschliesslich seine bisherige oeffentliche Identitaet. SSH-Clients
muessen diese geaenderte Hostidentitaet anschliessend bestaetigen. Markierte
Schluessel bleiben beim Neustart stabil. Lesefehler, beschaedigte Paare,
unbekannte Markierungen oder Entropie-/Batchfehler ersetzen keinen Bestand.

## Console input

Interactive shell input uses typed UTF-8 stream-byte events bound to the exact spawned process handle. The existing bounded byte queue and SSH receive-window credit retain unaccepted suffixes across packets and queue backpressure. UTF-8 decoding and ANSI key parsing belong to Terminal. CR/LF and DEL normalization remain at the existing channel boundary. The channel tests include split D0 81 and continuation-byte80 with partial acknowledgement and retry.
UTF8 path profile (0.85.42)
--------------------------
SFTP/SCP paths use the shared strict R4STD UTF8 transport validator before
normalization or filesystem operations. Original spaces and Unicode scalars
remain intact. NUL, ASCII controls, illegal path characters, partial/malformed
UTF8 and byte/UTF16-unit overflow fail explicitly. No normalization or guessed
legacy encoding is applied. Full path identities drive SCP names; SFTP long
names and entry buffers retain complete supported names instead of clipping.
ShellPath/SftpRoot retain the full1023-byte API capacity. Path/argument Registry
reads must be complete and valid before replacing defaults; invalid configured
values produce a controlled startup error. Existing byte-preserving SFTP/SCP
payload handling and staged publication/cleanup contracts remain unchanged.
The SSH channel transports bytes; incremental UTF8 decoding stays in Terminal.
NTFS $UpCase and FAT ASCII case comparison remain filesystem-owned. Existing
atomic-publication limits are explicit failures, including unsupported FAT
long-name publication; file data is never silently redirected or transcoded.
