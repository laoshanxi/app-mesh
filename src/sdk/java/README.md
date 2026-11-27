# App Mesh Java SDK

Java client for App Mesh. Group and artifact ID: `laoshanxi:appmesh`.

## Install from Maven Central

Maven Central is the standard channel. No repository or credential setup is needed.

```xml
<dependency>
    <groupId>laoshanxi</groupId>
    <artifactId>appmesh</artifactId>
    <version>3.0.24</version>
</dependency>
```

Maven Central is published by the manual `release-sdk-java` workflow (`workflow_dispatch`) when the repository Central Portal secrets are configured. The workflow skips a version that is already published.

## Install from GitHub Packages

GitHub Packages is the pre-release and private channel. It is a private Maven registry, so Maven must send a GitHub token, and this install path needs setup.

1. Create a classic personal access token with the `read:packages` scope.
2. Put this block in `~/.m2/settings.xml`. Replace the username and token placeholders with your GitHub login and the token:

```xml
<settings>
    <servers>
        <server>
            <id>github</id>
            <username>YOUR_GITHUB_USERNAME</username>
            <password>YOUR_GITHUB_TOKEN</password>
        </server>
    </servers>
    <profiles>
        <profile>
            <id>github</id>
            <repositories>
                <repository>
                    <id>github</id>
                    <url>https://maven.pkg.github.com/laoshanxi/app-mesh</url>
                    <releases>
                        <enabled>true</enabled>
                    </releases>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                </repository>
            </repositories>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>github</activeProfile>
    </activeProfiles>
</settings>
```

The repository `id` and the server `id` must both be `github`. Maven matches the credentials to the repository through this ID.

3. Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>laoshanxi</groupId>
    <artifactId>appmesh</artifactId>
    <version>3.0.24</version>
</dependency>
```

## Build from source

```shell
git clone https://github.com/laoshanxi/app-mesh.git
cd app-mesh/src/sdk/java
mvn package
```

The jar lands in `target/appmesh-<version>.jar`.

## Usage

```java
import appmesh.AppMeshClient;

AppMeshClient client = new AppMeshClient.Builder()
        .baseURL("https://127.0.0.1:6060")
        .build();
client.setBearerToken(System.getenv("APPMESH_BEARER_TOKEN"));

JSONObject app = new JSONObject().put("command", "echo hello from App Mesh");
Pair<Integer, String> result = client.runAppSync(app, 60);
System.out.println(result.getValue());
```

`AppMeshClientTCP` and `AppMeshClientWSS` speak the TCP (port 6062) and WebSocket (port 6063) transports. See the `appmesh` package javadoc for the full API.
