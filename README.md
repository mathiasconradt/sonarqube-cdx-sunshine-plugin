# SonarQube SBOM Visualization Plugin

A SonarQube plugin that brings the [CycloneDX Sunshine](https://github.com/CycloneDX/Sunshine) SBOM visualization directly into SonarQube, per project.

For each project it fetches the CycloneDX SBOM and dependency risk (CVE) data from SonarQube's SCA API, merges the vulnerability data into the SBOM, and renders the full Sunshine interactive visualization — sunburst dependency chart, components table, and vulnerabilities table — inside SonarQube.

![Build](https://github.com/mathiasconradt/sonarqube-sbom-visualization-plugin/actions/workflows/build.yml/badge.svg)

## Requirements

- SonarQube 2026.x (uses plugin API 12.x)
- SonarQube SCA (Software Composition Analysis) enabled and projects analyzed
- Java 17+ (build)
- Maven 3.8+ (build)

## How it works

1. A SonarQube token is stored once via the plugin's admin page.
2. When a user opens the **SBOM Visualization** tab on a project, the plugin backend calls two SonarQube SCA APIs:
   - `GET /api/v2/sca/sbom-reports?component={key}&type=cyclonedx` — the CycloneDX SBOM
   - `GET /api/v2/sca/risk-reports?component={key}` — dependency vulnerability risks
3. The Java backend merges CVE/risk data into the SBOM by matching `packageUrl` (purl).
4. The enriched CycloneDX JSON is passed to a JavaScript port of the Sunshine visualization engine, which renders:
   - An interactive sunburst chart of all dependencies, color-coded by highest vulnerability severity
   - A toggle to show only vulnerable components
   - A searchable, paginated components table with dependency relationships, direct/transitive vulnerabilities, and licenses
   - A searchable, paginated vulnerabilities table with affected components

## Build

```bash
mvn package
```

The plugin JAR is written to `target/sonarqube-cdx-sunshine-plugin-<version>.jar`.

## Deploy

### Standard

Copy the JAR to SonarQube's plugins directory and restart:

```bash
cp target/sonarqube-cdx-sunshine-plugin-*.jar $SONARQUBE_HOME/extensions/plugins/
# restart SonarQube
```

### Docker

If SonarQube runs in Docker with a named `sonarqube_extensions` volume:

```bash
mvn package

docker cp target/sonarqube-cdx-sunshine-plugin-*.jar \
  sonarqube:/opt/sonarqube/extensions/plugins/

docker restart sonarqube
```

`/opt/sonarqube/extensions/plugins/` sits on the `sonarqube_extensions` named volume, so it remains writable even when the container runs with `read_only: true`.

To remove the plugin:

```bash
docker exec sonarqube rm /opt/sonarqube/extensions/plugins/sonarqube-cdx-sunshine-plugin-*.jar
docker restart sonarqube
```

## Configuration

1. Log in to SonarQube as admin.
2. Go to **Administration → Configuration → SBOM Visualization**.
3. Enter a SonarQube token with permission to read project SBOM and SCA data and click **Save**.

The token is stored as a global SonarQube setting (`sbomviz.sonar.token`).

## Pages

| Page | Location in SonarQube |
|------|-----------------------|
| Token configuration | Administration → Configuration → SBOM Visualization |
| Per-project visualization | Project → Analysis → SBOM Visualization |

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE).

### Third-party components

**Visualization logic** — [`src/main/resources/static/project.js`](src/main/resources/static/project.js) is a JavaScript port of the Python implementation from [CycloneDX Sunshine](https://github.com/CycloneDX/Sunshine):

> Copyright (c) OWASP Foundation. All Rights Reserved.
> SPDX-License-Identifier: Apache-2.0

**Chart library** — [`src/main/resources/static/echarts.min.js`](src/main/resources/static/echarts.min.js) is [Apache ECharts](https://echarts.apache.org/):

> Copyright (c) Apache Software Foundation.
> SPDX-License-Identifier: Apache-2.0