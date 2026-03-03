# Metakit SDK Publishing Guide

Complete steps to finish setup and publish the SDK packages to their respective registries.

## Prerequisites

- Admin access to the `Constellation-Labs/metakit-sdk` GitHub repository
- npm account with access to the `@constellation-network` organization (TypeScript)
- PyPI account with access to publish `constellation-metagraph-sdk` (Python)
- crates.io account with access to publish `constellation-metagraph-sdk` (Rust)
- Maven Central/Sonatype account (Java)
- Go modules are published automatically via GitHub tags

---

## Step 1: Commit and Push Initial Code

```bash
cd /home/scas/git/metakit-sdk

# Stage all files
git add .

# Commit
git commit -m "Initial monorepo setup with TypeScript and Python SDKs

- TypeScript SDK: @constellation-network/metagraph-sdk
- Python SDK: constellation-metagraph-sdk
- CI/CD with GitHub Actions
- Cross-language test vectors
- Dependabot configuration"

# Push to main
git push origin main
```

---

## Step 2: Verify CI Passes

1. Go to https://github.com/Constellation-Labs/metakit-sdk/actions
2. Wait for the CI workflow to complete
3. Ensure all jobs pass:
   - TypeScript tests (Node 18, 20, 22)
   - Python tests (Python 3.10, 3.11, 3.12)
   - Rust tests (stable)
   - Go tests (1.18, 1.21, 1.22)
   - Java tests (11, 17, 21)
   - Cross-language compatibility tests

**If CI fails**: Fix the issues and push again before proceeding.

---

## Step 3: Configure npm Publishing

### 3.1 Create npm Access Token

1. Log in to https://www.npmjs.com
2. Go to **Access Tokens** → **Generate New Token**
3. Select **Automation** token type
4. Name it `metakit-sdk-github-actions`
5. Copy the token (starts with `npm_`)

### 3.2 Add Token to GitHub Secrets

1. Go to https://github.com/Constellation-Labs/metakit-sdk/settings/secrets/actions
2. Click **New repository secret**
3. Name: `NPM_TOKEN`
4. Value: Paste the npm token
5. Click **Add secret**

---

## Step 4: Configure PyPI Trusted Publishing

PyPI trusted publishing uses OpenID Connect (OIDC) - no secrets needed!

### 4.1 Add Trusted Publisher on PyPI

1. Log in to https://pypi.org
2. If project doesn't exist yet, create a "pending publisher" at https://pypi.org/manage/account/publishing/
3. For the project `constellation-metagraph-sdk`:
   - Go to **Manage** → **Publishing**
   - Under **Trusted Publishers**, click **Add a new publisher**
4. Fill in:
   - **Owner**: `Constellation-Labs`
   - **Repository name**: `metakit-sdk`
   - **Workflow name**: `release-python.yml`
   - **Environment name**: (leave blank)
5. Click **Add**

---

## Step 5: Release TypeScript SDK

### 5.1 Verify Version

Ensure `packages/typescript/package.json` has the correct version:

```bash
grep '"version"' packages/typescript/package.json
```

### 5.2 Create and Push Tag

```bash
# Create annotated tag
git tag -a typescript-v0.1.0 -m "TypeScript SDK v0.1.0"

# Push tag to trigger release
git push origin typescript-v0.1.0
```

### 5.3 Monitor Release

1. Watch the workflow at https://github.com/Constellation-Labs/metakit-sdk/actions
2. Once complete, verify:
   - GitHub Release created: https://github.com/Constellation-Labs/metakit-sdk/releases
   - npm package published: https://www.npmjs.com/package/@constellation-network/metagraph-sdk

---

## Step 6: Release Python SDK

### 6.1 Verify Version

Ensure `packages/python/pyproject.toml` has the correct version:

```bash
grep 'version' packages/python/pyproject.toml | head -1
```

### 6.2 Create and Push Tag

```bash
# Create annotated tag
git tag -a python-v0.1.0 -m "Python SDK v0.1.0"

# Push tag to trigger release
git push origin python-v0.1.0
```

### 6.3 Monitor Release

1. Watch the workflow at https://github.com/Constellation-Labs/metakit-sdk/actions
2. Once complete, verify:
   - GitHub Release created: https://github.com/Constellation-Labs/metakit-sdk/releases
   - PyPI package published: https://pypi.org/project/constellation-metagraph-sdk/

---

## Step 7: Release Rust SDK

### 7.1 Configure crates.io Token

1. Log in to https://crates.io
2. Go to **Account Settings** → **API Tokens**
3. Create a new token with publish permissions
4. Add to GitHub Secrets as `CRATES_TOKEN`

### 7.2 Verify Version

Ensure `packages/rust/Cargo.toml` has the correct version:

```bash
grep '^version' packages/rust/Cargo.toml
```

### 7.3 Create and Push Tag

```bash
git tag -a rust-v0.1.0 -m "Rust SDK v0.1.0"
git push origin rust-v0.1.0
```

---

## Step 8: Release Go SDK

Go modules are published automatically when you push a tag. No additional configuration needed.

### 8.1 Verify Version

Update version in `packages/go/go.mod` if using semantic versioning.

### 8.2 Create and Push Tag

```bash
git tag -a packages/go/v0.1.0 -m "Go SDK v0.1.0"
git push origin packages/go/v0.1.0
```

### 8.3 Verify on pkg.go.dev

After pushing, the module will be available at:
https://pkg.go.dev/github.com/Constellation-Labs/metakit-sdk/packages/go

---

## Step 9: Release Java SDK

### 9.1 Configure Maven Central

For publishing to Maven Central, you'll need:
1. Sonatype OSSRH account
2. GPG key for signing
3. Add secrets to GitHub: `MAVEN_USERNAME`, `MAVEN_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`

### 9.2 Verify Version

Ensure `packages/java/pom.xml` has the correct version:

```bash
grep '<version>' packages/java/pom.xml | head -1
```

### 9.3 Create and Push Tag

```bash
git tag -a java-v0.1.0 -m "Java SDK v0.1.0"
git push origin java-v0.1.0
```

---

## Step 10: Post-Release Verification

### Test npm Installation

```bash
mkdir /tmp/test-ts-sdk && cd /tmp/test-ts-sdk
npm init -y
npm install @constellation-network/metagraph-sdk

node -e "
const { generateKeyPair } = require('@constellation-network/metagraph-sdk');
const kp = generateKeyPair();
console.log('Generated address:', kp.address);
"
```

### Test PyPI Installation

```bash
mkdir /tmp/test-py-sdk && cd /tmp/test-py-sdk
python3 -m venv venv && source venv/bin/activate
pip install constellation-metagraph-sdk

python3 -c "
from constellation_sdk import generate_key_pair
kp = generate_key_pair()
print('Generated address:', kp.address)
"
```

### Test Rust Installation

```bash
mkdir /tmp/test-rs-sdk && cd /tmp/test-rs-sdk
cargo init
echo 'constellation-metagraph-sdk = "0.1"' >> Cargo.toml

cat > src/main.rs << 'EOF'
use constellation_sdk::wallet::generate_key_pair;

fn main() {
    let kp = generate_key_pair();
    println!("Generated address: {}", kp.address);
}
EOF

cargo run
```

### Test Go Installation

```bash
mkdir /tmp/test-go-sdk && cd /tmp/test-go-sdk
go mod init test
go get github.com/Constellation-Labs/metakit-sdk/packages/go

cat > main.go << 'EOF'
package main

import (
    "fmt"
    constellation "github.com/Constellation-Labs/metakit-sdk/packages/go"
)

func main() {
    kp, _ := constellation.GenerateKeyPair()
    fmt.Println("Generated address:", kp.Address)
}
EOF

go run main.go
```

### Test Java Installation

```bash
mkdir /tmp/test-java-sdk && cd /tmp/test-java-sdk

cat > pom.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>test</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>io.constellationnetwork</groupId>
            <artifactId>metagraph-sdk</artifactId>
            <version>0.1.0</version>
        </dependency>
    </dependencies>
</project>
EOF

cat > src/main/java/Test.java << 'EOF'
import io.constellationnetwork.metagraph.sdk.*;

public class Test {
    public static void main(String[] args) {
        Types.KeyPair kp = Wallet.generateKeyPair();
        System.out.println("Generated address: " + kp.getAddress());
    }
}
EOF

mvn compile exec:java -Dexec.mainClass=Test
```

---

## Future Releases

To release a new version:

1. **Update version** in package config:
   - TypeScript: `packages/typescript/package.json`
   - Python: `packages/python/pyproject.toml`
   - Rust: `packages/rust/Cargo.toml`
   - Go: Tag only (no version file)
   - Java: `packages/java/pom.xml`

2. **Commit and push**:
   ```bash
   git add .
   git commit -m "chore: bump version to X.Y.Z"
   git push origin main
   ```

3. **Create and push tag** for the language(s) being released:
   ```bash
   # TypeScript
   git tag -a typescript-vX.Y.Z -m "TypeScript SDK vX.Y.Z"
   git push origin typescript-vX.Y.Z

   # Python
   git tag -a python-vX.Y.Z -m "Python SDK vX.Y.Z"
   git push origin python-vX.Y.Z

   # Rust
   git tag -a rust-vX.Y.Z -m "Rust SDK vX.Y.Z"
   git push origin rust-vX.Y.Z

   # Go
   git tag -a packages/go/vX.Y.Z -m "Go SDK vX.Y.Z"
   git push origin packages/go/vX.Y.Z

   # Java
   git tag -a java-vX.Y.Z -m "Java SDK vX.Y.Z"
   git push origin java-vX.Y.Z
   ```

4. **Verify** the release workflow completes successfully

---

## Troubleshooting

### npm publish fails with 403

- Verify `NPM_TOKEN` secret is set correctly
- Verify token has publish permissions
- Verify account has access to `@constellation-network` org

### PyPI publish fails with "trusted publisher not found"

- Ensure trusted publisher is configured exactly as:
  - Owner: `Constellation-Labs`
  - Repository: `metakit-sdk`
  - Workflow: `release-python.yml`
- If package doesn't exist, create a pending publisher first

### Version mismatch error

The release workflows verify that the package version matches the tag. If you see:
```
Package version (X.X.X) does not match tag (Y.Y.Y)
```

Update the version in the package config file, commit, and push before creating the tag.

### Manual workflow run

You can manually trigger the release workflows from the Actions tab using "Run workflow". This is useful for testing but won't publish (publish steps only run on tag push).

---

## Quick Reference

| Language | Version File | Tag Format | Package Registry |
|----------|--------------|------------|------------------|
| TypeScript | `packages/typescript/package.json` | `typescript-v0.1.0` | npm: `@constellation-network/metagraph-sdk` |
| Python | `packages/python/pyproject.toml` | `python-v0.1.0` | PyPI: `constellation-metagraph-sdk` |
| Rust | `packages/rust/Cargo.toml` | `rust-v0.1.0` | crates.io: `constellation-metagraph-sdk` |
| Go | (tag only) | `packages/go/v0.1.0` | pkg.go.dev (automatic) |
| Java | `packages/java/pom.xml` | `java-v0.1.0` | Maven Central: `io.constellationnetwork:metagraph-sdk` |