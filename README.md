# APK URL Hunter

A standalone Go tool for extracting URLs and potential secrets from Android APKs
or already-decompiled app folders. Scans files in parallel and records the source
path for every match.
No Python, Java, JADX, APK installation, or network access is required.

The pattern rules are derived from [APKLeaks](https://github.com/dwisiswant0/apkleaks)
by dwisiswant0 under Apache-2.0. This is a separate implementation; it is not an
official upstream release. See [NOTICE](NOTICE) for the rule adaptations.

## Build

Requires Go 1.22 or newer. There are no external Go dependencies.

```sh
go test ./...
go build -trimpath -ldflags="-s -w" -o apk-url-hunter .
```

On Windows, use `-o apk-url-hunter.exe` and run `./apk-url-hunter.exe`.

## Usage

URLs plus the bundled pattern rules:

```sh
./apk-url-hunter -f app.apk --json -o findings.json
```

Fast URL extraction only:

```sh
./apk-url-hunter -f app.apk --urls-only --json -o urls.json
```

Custom rules:

```sh
./apk-url-hunter -f app.apk -p custom-rules.json --json -o custom.json
```

```json
{
  "InternalEndpoint": "https://api\\.example\\.invalid/[a-z/]+",
  "Markers": ["example-marker-one", "example-marker-two"]
}
```

Custom expressions must use Go/RE2 syntax. Lookbehind, lookahead, and
backreferences are not supported; invalid patterns fail with the rule name.
An optional named capture `(?P<match>...)` returns only that capture.
The bundled JWT rule additionally requires a letter and a digit, matching its
upstream validation. All matches, rather than only the first per line, are kept.

Scan an already-decompiled app folder (JADX, Apktool, or another tool):

```sh
./apk-url-hunter -d "path/to/decompiled app" --json -o folder-findings.json
./apk-url-hunter -d "path/to/decompiled app" --urls-only --json -o folder-urls.json
```

Choose exactly one of `-f` and `-d`. Folder mode recursively scans regular files
using the same rules and worker pool as APK mode. Sources are forward-slash paths
relative to the input directory. Symlinks, directory junctions, and special files
are skipped; a symlink/junction cannot be used as the input root. Read errors fail
the scan. Keep the folder unchanged while scanning. The current output file is
excluded automatically, including when it is created inside the input folder.

| Option | Meaning |
| --- | --- |
| `-f` | Input APK file; mutually exclusive with `-d` |
| `-d` | Already-decompiled app directory; mutually exclusive with `-f` |
| `-o` | New output file; existing files are never overwritten |
| `--json` | JSON output; otherwise human-readable text |
| `--urls-only` | Skip all secret/pattern rules |
| `-p` | Replace bundled rules with a custom JSON file |

Default output is `apk-url-hunter-results.txt` or `apk-url-hunter-results.json`.
Only counts, timing, and the output path are printed to the terminal; matched
values stay in the output file. JSON contains:

- `apk`: APK filename, present in APK mode only.
- `directory`: input folder name, present in folder mode only.
- `entries`: number of scanned archive entries or regular files.
- `seconds`: elapsed scanning time.
- `urls`: unique URLs with their `sources` entry names.
- `findings`: unique `name`/`value` pattern matches with `sources` entry names.

Results are sorted and deduplicated. Empty results are valid and still saved.

## Coverage and limits

URL extraction handles literal HTTP/HTTPS/WS/WSS/www strings, JSON-escaped
slashes, and ASCII URLs stored in UTF-16LE/BE. Pattern rules also scan those
text views. Binary NUL separators become line boundaries for anchored rules.

This version does not decompile code, parse the Android package identifier,
reconstruct runtime-generated strings, decrypt content, or recurse into nested
archives. Consequently it is not a drop-in replacement for all JADX-based
APKLeaks results, and a lack of matches does not prove an app contains no secrets.

Library URLs, documentation URLs, IP addresses, and broad regex matches can be
noise. Findings are candidates, not verified credentials or vulnerabilities.
The tool never contacts the discovered endpoints or validates credentials.
Keep output files private; they may contain real secrets or personal data.

At most eight workers run concurrently. Inputs exceeding 128 MiB per expanded
entry/file or 1 GiB expanded total are rejected. ZIP integrity errors fail the scan;
archive entries are never extracted as filesystem paths. Failed scans remove
only the new output file created by that invocation.

## Measured performance

On a local 34.8 MB APK with 2,762 entries:

| Mode | Time | Results |
| --- | --- | --- |
| URLs only | 1.165 s | 254 unique URLs |
| URLs plus bundled rules | 17.687 s | 254 URLs and 926 pattern candidates |

These are single Windows runs, not a cross-machine benchmark or an equivalence
claim against decompiler-based scanning.

## Development

```sh
go test ./...
go vet ./...
```

CI runs the tests and build on Windows, Linux, and macOS. APK samples and scan
results are not included in this repository. Use only APKs you are permitted to
analyze.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
