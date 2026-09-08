# SSHD.R4X

`SSHD.R4X` is an independent R4OS service implemented in Zig.

## Package

- Version: `0.1.9`
- Image target: `/R4OS/SERVICES/SSHD.R4X`
- Image scope: `full`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

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
