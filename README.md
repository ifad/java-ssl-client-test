# Java eMudhra certificate check

This command requests HTTPS URLs and reports whether the current JVM accepts their certificates, like a minimal `curl` for Java. It is useful with the [eMudhra compromised-intermediate test sites](https://emudhra.we-have-a-problem.com/). It uses the JVM's normal certificate and hostname validation. Run it with the same JDK, trust store, and security settings as the application you want to assess.

```sh
java -jar IFADHttpsClientTest-java8.jar https://dv-g3b-emudhra.we-have-a-problem.com/ https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
```

Pass one or more HTTPS URLs; with none, it prints usage and exits 2. Each release has one JAR per Java version, `IFADHttpsClientTest-java<N>.jar` for N from 7 through 27. Use the JAR matching the JVM you want to assess.

`REJECTED` means Java rejected the certificate; `TRUSTED` means it completed an HTTPS request and accepted the certificate chain. `ERROR` means the check was inconclusive, for example because DNS, connectivity, or TLS negotiation failed. Exit codes are 0 when every URL was rejected, 1 when any URL was trusted, and 2 when no URL was trusted but at least one check was inconclusive. Java 7 uses TLS 1.2 explicitly so its default protocol selection does not prevent the certificate check.

To build one JAR locally (default 7; Gradle 7.4 needs JDK 17 or older): `./gradlew build -PjavaVersion=11`.

GitHub Actions builds each JAR with `javac` inside the matching `azul/zulu-openjdk:<N>` image (`azul-zulu:27` for Java 27), then runs the two eMudhra test URLs against it. A `TRUSTED` result is recorded but does not fail CI; an inconclusive check does. Pushing a `v*` tag, such as `v1.1.0`, creates a GitHub Release with all JARs after CI passes. The release workflow does not change the trust store on any machine.

Some older Java versions use Azul's legacy `azul/zulu-openjdk` image repository. Azul says it will retire that repository by the end of 2026, so those CI images will need another source then.
