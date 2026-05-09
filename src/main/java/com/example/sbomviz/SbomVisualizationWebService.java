/*
 * SonarQube SBOM Visualization Plugin
 * Copyright (C) 2024-present Mathias Conradt
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.sbomviz;

import com.google.gson.*;
import org.sonar.api.config.Configuration;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.ws.Request;
import org.sonar.api.server.ws.Response;
import org.sonar.api.server.ws.WebService;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@ServerSide
public class SbomVisualizationWebService implements WebService {

    private final Configuration configuration;
    private final Path cacheDir;

    public SbomVisualizationWebService(Configuration configuration) {
        this.configuration = configuration;
        this.cacheDir = Paths.get(System.getProperty("java.io.tmpdir"), "sbomviz-cache");
        try {
            Files.createDirectories(cacheDir);
        } catch (IOException ignored) {
        }
    }

    @Override
    public void define(Context context) {
        NewController controller = context.createController("api/sbomviz");
        controller.setDescription("SBOM Visualization API");

        NewAction dataAction = controller.createAction("data")
            .setDescription("Get enriched SBOM data for a project")
            .setHandler(this::getData)
            .setInternal(true);
        dataAction.createParam("projectKey")
            .setRequired(true)
            .setDescription("The SonarQube project key");
        dataAction.createParam("branch")
            .setRequired(false)
            .setDescription("Branch name (defaults to main branch)");
        dataAction.createParam("noCache")
            .setRequired(false)
            .setDescription("Skip cache and force regeneration");

        NewAction branchesAction = controller.createAction("branches")
            .setDescription("List branches for a project")
            .setHandler(this::getBranches)
            .setInternal(true);
        branchesAction.createParam("projectKey")
            .setRequired(true)
            .setDescription("The SonarQube project key");

        controller.done();
    }

    private void getBranches(Request request, Response response) throws Exception {
        String projectKey = request.mandatoryParam("projectKey");
        String token = configuration.get("sbomviz.sonar.token").orElse("").trim();

        if (token.isEmpty()) {
            writeJsonError(response, "SonarQube token not configured.");
            return;
        }

        String baseUrl = baseUrl();
        try {
            String encodedKey = URLEncoder.encode(projectKey, StandardCharsets.UTF_8);
            String branchesJson = fetchUrl(
                baseUrl + "/api/project_branches/list?project=" + encodedKey,
                token, null
            );
            response.stream().setMediaType("application/json");
            response.stream().output().write(branchesJson.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            writeJsonError(response, "Failed to fetch branches: " + e.getMessage());
        }
    }

    private void getData(Request request, Response response) throws Exception {
        String projectKey = request.mandatoryParam("projectKey");
        String branch = request.param("branch");
        boolean noCache = "true".equalsIgnoreCase(request.param("noCache"));
        String token = configuration.get("sbomviz.sonar.token").orElse("").trim();

        if (token.isEmpty()) {
            writeJsonError(response, "SonarQube token not configured. Please set it in Administration → Configuration → SBOM Visualization.");
            return;
        }

        String baseUrl = baseUrl();
        Gson gson = new GsonBuilder().serializeNulls().create();

        try {
            String encodedKey = URLEncoder.encode(projectKey, StandardCharsets.UTF_8);
            String branchSuffix = (branch != null && !branch.isBlank())
                ? "&branch=" + URLEncoder.encode(branch, StandardCharsets.UTF_8)
                : "";

            // check last analysis date
            Instant lastAnalysis = fetchLastAnalysisDate(baseUrl, encodedKey, branchSuffix, token, gson);

            // check cache (skip if noCache=true)
            Path cacheFile = cacheFile(projectKey, branch);
            if (!noCache && lastAnalysis != null && Files.exists(cacheFile)) {
                try {
                    String cached = new String(Files.readAllBytes(cacheFile), StandardCharsets.UTF_8);
                    JsonObject cachedObj = gson.fromJson(cached, JsonObject.class);
                    if (cachedObj.has("generatedAt")) {
                        Instant cachedAt = Instant.parse(cachedObj.get("generatedAt").getAsString());
                        if (!cachedAt.isBefore(lastAnalysis)) {
                            // cache is fresh
                            response.stream().setMediaType("application/json");
                            response.stream().output().write(cached.getBytes(StandardCharsets.UTF_8));
                            return;
                        }
                    }
                } catch (Exception ignored) {
                    // corrupt cache — fall through to refresh
                }
            }

            // fetch fresh data
            String sbomJson = fetchUrl(
                baseUrl + "/api/v2/sca/sbom-reports?component=" + encodedKey + "&type=cyclonedx" + branchSuffix,
                token, "application/vnd.cyclonedx+json"
            );
            String risksJson = fetchUrl(
                baseUrl + "/api/v2/sca/risk-reports?component=" + encodedKey + branchSuffix,
                token, null
            );

            JsonObject sbom = gson.fromJson(sbomJson, JsonObject.class);
            JsonElement risksEl = gson.fromJson(risksJson, JsonElement.class);
            JsonArray risks = risksEl.isJsonArray() ? risksEl.getAsJsonArray() : new JsonArray();
            JsonObject enriched = mergeRisksIntoSbom(sbom, risks);

            String generatedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
            JsonObject result = new JsonObject();
            result.add("sbom", enriched);
            result.addProperty("generatedAt", generatedAt);
            if (lastAnalysis != null) {
                result.addProperty("lastAnalysisDate", DateTimeFormatter.ISO_INSTANT.format(lastAnalysis));
            }

            String resultJson = gson.toJson(result);

            // write to cache
            try {
                Files.write(cacheFile, resultJson.getBytes(StandardCharsets.UTF_8));
            } catch (IOException ignored) {
            }

            response.stream().setMediaType("application/json");
            response.stream().output().write(resultJson.getBytes(StandardCharsets.UTF_8));

        } catch (IOException e) {
            writeJsonError(response, "Failed to fetch data from SonarQube API: " + e.getMessage());
        }
    }

    private Instant fetchLastAnalysisDate(String baseUrl, String encodedKey, String branchSuffix,
                                          String token, Gson gson) {
        try {
            // branchSuffix uses &branch=... but analyses API uses &branch=... too — strip leading &
            String branchParam = branchSuffix.isEmpty() ? "" : branchSuffix; // already "&branch=..."
            String url = baseUrl + "/api/project_analyses/search?project=" + encodedKey
                + branchParam + "&ps=1";
            String json = fetchUrl(url, token, null);
            JsonObject obj = gson.fromJson(json, JsonObject.class);
            if (obj.has("analyses")) {
                JsonArray analyses = obj.getAsJsonArray("analyses");
                if (analyses.size() > 0) {
                    String date = analyses.get(0).getAsJsonObject().get("date").getAsString();
                    // SQ returns "+0000" (no colon); try ISO first, then pattern-based fallback
                    try {
                        return Instant.from(DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(date));
                    } catch (Exception e) {
                        return OffsetDateTime.parse(date,
                            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ")).toInstant();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private Path cacheFile(String projectKey, String branch) {
        String safeName = (projectKey + "_" + (branch != null ? branch : "default"))
            .replaceAll("[^a-zA-Z0-9._-]", "_");
        return cacheDir.resolve(safeName + ".json");
    }

    private String baseUrl() {
        int port = configuration.getInt("sonar.web.port").orElse(9000);
        String ctx = configuration.get("sonar.web.context").orElse("").replaceAll("/$", "");
        return "http://localhost:" + port + ctx;
    }

    private void writeJsonError(Response response, String message) throws IOException {
        JsonObject err = new JsonObject();
        err.addProperty("error", message);
        response.stream().setMediaType("application/json");
        response.stream().output().write(new Gson().toJson(err).getBytes(StandardCharsets.UTF_8));
    }

    private String fetchUrl(String urlStr, String token, String accept) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(30_000);
        conn.setReadTimeout(120_000);
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
        if (accept != null) {
            conn.setRequestProperty("Accept", accept);
        }

        int code = conn.getResponseCode();
        if (code == 401) throw new IOException("Authentication failed (401). Check your SonarQube token in plugin settings.");
        if (code == 403) throw new IOException("Access forbidden (403). Token lacks required permissions.");
        if (code == 404) throw new IOException("Not found (404). Project may not have an SBOM. Ensure SCA is enabled and the project has been analyzed.");
        if (code != 200) throw new IOException("HTTP " + code + " from SonarQube API at " + urlStr);

        try (InputStream is = conn.getInputStream();
             BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }

    private JsonObject mergeRisksIntoSbom(JsonObject sbom, JsonArray risks) {
        Map<String, JsonArray> risksMap = new HashMap<>();
        for (JsonElement el : risks) {
            if (!el.isJsonObject()) continue;
            JsonObject risk = el.getAsJsonObject();
            if (!risk.has("packageUrl")) continue;
            String purl = risk.get("packageUrl").getAsString();
            risksMap.computeIfAbsent(purl, k -> new JsonArray()).add(risk);
        }

        if (sbom.has("components")) {
            for (JsonElement el : sbom.getAsJsonArray("components")) {
                if (!el.isJsonObject()) continue;
                JsonObject comp = el.getAsJsonObject();
                if (!comp.has("purl")) continue;
                String purl = comp.get("purl").getAsString();
                JsonArray matching = risksMap.get(purl);
                if (matching == null) continue;

                if (!comp.has("vulnerabilities")) {
                    comp.add("vulnerabilities", new JsonArray());
                }
                JsonArray vulns = comp.getAsJsonArray("vulnerabilities");
                for (JsonElement riskEl : matching) {
                    vulns.add(formatVulnerability(riskEl.getAsJsonObject()));
                }
            }
        }
        return sbom;
    }

    private JsonObject formatVulnerability(JsonObject risk) {
        JsonObject vuln = new JsonObject();
        if (risk.has("vulnerabilityId")) {
            vuln.addProperty("id", risk.get("vulnerabilityId").getAsString());
        }
        JsonObject source = new JsonObject();
        source.addProperty("name", "SonarQube");
        vuln.add("source", source);

        JsonArray ratings = new JsonArray();
        String severity = risk.has("riskSeverity") ? mapSeverity(risk.get("riskSeverity").getAsString()) : "info";
        JsonObject rating = new JsonObject();
        rating.addProperty("severity", severity);
        rating.addProperty("method", "CVSSv3");
        if (risk.has("cvssScore")) rating.addProperty("score", risk.get("cvssScore").getAsDouble());
        ratings.add(rating);
        vuln.add("ratings", ratings);

        if (risk.has("cweIds")) {
            JsonArray cwes = new JsonArray();
            for (JsonElement cweEl : risk.getAsJsonArray("cweIds")) {
                String cwe = cweEl.getAsString();
                if (cwe.contains("-")) {
                    try { cwes.add(Integer.parseInt(cwe.split("-")[1])); } catch (NumberFormatException ignored) {}
                }
            }
            if (cwes.size() > 0) vuln.add("cwes", cwes);
        }
        if (risk.has("riskTitle")) vuln.addProperty("description", risk.get("riskTitle").getAsString());
        return vuln;
    }

    private String mapSeverity(String s) {
        switch (s.toUpperCase()) {
            case "CRITICAL": return "critical";
            case "HIGH":     return "high";
            case "MEDIUM":   return "medium";
            case "LOW":      return "low";
            default:         return "info";
        }
    }
}
