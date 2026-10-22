# Java eMudhra certificate check

This command checks whether the current JVM accepts either of two [eMudhra compromised-intermediate test sites](https://emudhra.we-have-a-problem.com/). It uses the JVM's normal certificate and hostname validation. Run it with the same JDK, trust store, and security settings as the application you want to assess.

```sh
./gradlew build
java -jar build/libs/IFADHttpsClientTest-1.0.jar
```

The no-argument command requests these two URLs:

```text
https://dv-g3b-emudhra.we-have-a-problem.com/
https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
```

You can pass one or more HTTPS URLs instead. For example:

```sh
java -jar build/libs/IFADHttpsClientTest-1.0.jar https://dv-g3b-emudhra.we-have-a-problem.com/
```

`REJECTED` means Java rejected the certificate; `TRUSTED` means it completed an HTTPS request and accepted the certificate chain. `ERROR` means the check was inconclusive, for example because DNS, connectivity, or TLS negotiation failed. Exit codes are 0 when every URL was rejected, 1 when any URL was trusted, and 2 when no URL was trusted but at least one check was inconclusive. Java 7 uses TLS 1.2 explicitly so its default protocol selection does not prevent the certificate check.

The build produces one Java 7 bytecode JAR. GitHub Actions builds it in a Java 17 Docker image, then runs the live check in Docker images for every Java major version from 7 through 27 (the latest GA release as of October 2026). A `TRUSTED` result is recorded but does not fail CI; an inconclusive check does. Pushing a `v*` tag, such as `v1.1.0`, creates a GitHub Release with the JAR after CI passes. The release workflow does not change the trust store on any machine.

Some older Java versions use Azul's legacy `azul/zulu-openjdk` image repository. Azul says it will retire that repository by the end of 2026, so those CI images will need another source then.
