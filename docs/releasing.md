# Releasing

How a new version reaches Maven Central. Maintainers only.

**A published version is permanent.** Central does not allow deleting or replacing a release,
so the number you publish is the number that exists forever. The steps below are ordered so
the irreversible one comes last and is a deliberate click rather than a side effect.

## One-time setup

- The `io.github.rootect` namespace, verified against the GitHub account of the same name.
- A GPG key with its public half published to a keyserver. Central verifies every signature
  against it, so a key that is not published fails validation.
- A Central Portal account.

## Every release

### 1. Bump the version

`VERSION_NAME` in `gradle.properties` is the single source for the published coordinates.
Update version examples and release metadata where appropriate.

### 2. Build the signed bundle

```bash
REPO_ROOT="$PWD"  # Run from the repository root.
export SIGNING_KEY="$(gpg --armor --export-secret-keys <KEY_ID>)"
export SIGNING_PASSWORD='<passphrase>'
./gradlew publish
```

Writes to `rootect-core/build/release-bundle`. Nothing leaves the machine — the only
publishing repository is a local directory, so no Gradle task can upload by accident.

### 3. Verify the signatures

Signing is skipped when the environment variables are absent and the build still succeeds, so
check rather than assume:

```bash
(
cd rootect-core/build/release-bundle/io/github/rootect/rootect-core/<version>
for suffix in aar pom module sources.jar javadoc.jar; do
    case "$suffix" in *jar) f="rootect-core-<version>-${suffix}" ;;
        *) f="rootect-core-<version>.${suffix}" ;; esac
    test -f "$f" && test -f "$f.asc" && gpg --verify "$f.asc" "$f" || exit 1
done
)
```

Replace `<version>` in every command with the release version. Use a fresh release build
directory to avoid stale signatures. The current javadoc jar is an empty placeholder.

Expect five `Good signature` lines: the AAR, the POM, the module metadata, the sources jar and
the javadoc jar. An unsigned bundle is the most common reason Central rejects an upload.

### 4. Zip it

Central expects the `io/` tree at the root of the archive, and does not want
`maven-metadata.xml`:

```bash
cd "$REPO_ROOT/rootect-core/build/release-bundle"
python -c "
import zipfile, os
with zipfile.ZipFile('../release-bundle.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk('io/github/rootect/rootect-core/<version>'):
        for f in files:
            if 'maven-metadata' not in f:
                p = os.path.join(root, f)
                z.write(p, p.replace(os.sep, '/'))
"
```

### 5. Upload

At [central.sonatype.com/publishing](https://central.sonatype.com/publishing) choose **Publish
Component** and upload the zip. It validates and then stops, waiting for you.

### 6. Read the report, then decide

`VALIDATED` means Central accepted the signatures and the metadata. Nothing is public yet.

- **Drop** discards the deployment and leaves the version number free. This is how a dry run
  ends.
- **Publish** is the irreversible one. The artifact reaches Maven Central within minutes and
  appears in search within a few hours.

### 7. Tag the commit

```bash
git tag -a v<version> -m "v<version>"
git push origin v<version>
```

Tag the commit the artifacts were built from, so a published sources jar can always be traced
back to the tree that produced it.

## If validation fails

The report names the file and the rule. The usual causes:

| Symptom | Cause |
|---|---|
| Missing signature | `SIGNING_KEY` / `SIGNING_PASSWORD` were not set for the build |
| Signature cannot be verified | The public key was never pushed to a keyserver, or has not propagated |
| Missing sources or javadoc | The publication was built without them; both are required |
| Namespace not allowed | Signed in as an account that does not own `io.github.rootect` |

A failed deployment can be dropped and re-uploaded. The version number is only consumed once
something is actually published.
