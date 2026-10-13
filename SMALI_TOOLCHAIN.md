# Smali / DEX backend setup

DroidForensics does not synthesize DEX bytecode in the browser. DEX conversion is performed by the official Smali assembler and independently checked by Baksmali.

## Runtime requirements

Configure the server runtime with:

- A compatible Java runtime.
- The official Smali assembler JAR.
- The official Baksmali disassembler JAR.
- `JAVA_BIN` (normally `java`).
- `SMALI_JAR_PATH` and `BAKSMALI_JAR_PATH` as filesystem paths readable by the server.

Copy `.env.example` and update the paths for your environment. Do not place JAR paths in frontend configuration or serve the JARs to the browser.

If either JAR path is unset or the tools cannot start, the conversion endpoint returns a clear error and does not emit a DEX file.

## Available backend routes

- `POST /api/assemble-smali-zip` — request body is the raw Smali ZIP with content type `application/zip`; an optional `root` query parameter selects one DEX root.
- `POST /api/disassemble-dex?filename=classes10.dex` — request body is the raw DEX with content type `application/vnd.android.dex`; returns a Baksmali ZIP.

The server validates archive paths, rejects duplicate class descriptors and multiple unselected DEX roots, enforces size/time limits, checks DEX header/signature/checksum, and round-trips the result through Baksmali before returning a file.

## Important limitations

A successful assembly/round-trip is static validation, not a guarantee that an APK behaves correctly at runtime. Compare class/method integrity with the original and test on a non-production device.

APK rebuild, zip alignment, and real APK signing are not enabled by this workflow. Do not package the returned DEX into an APK until you separately rebuild and sign the APK with a proper Android toolchain.
