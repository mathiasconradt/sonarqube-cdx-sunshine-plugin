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
package io.github.mathiasconradt.sbomviz;

import com.google.gson.*;
import org.sonar.api.config.Configuration;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.ws.LocalConnector;
import org.sonar.api.server.ws.Request;
import org.sonar.api.server.ws.Response;
import org.sonar.api.server.ws.WebService;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@ServerSide
public class SbomVisualizationWebService implements WebService {

    // S1192 — duplicate string literals extracted to constants
    private static final String GENERATED_AT = "generatedAt";
    private static final String LARGE_GRAPH_LIMITS = "largeGraphLimits";
    private static final String PARAM_PROJECT_KEY = "projectKey";
    private static final String APPLICATION_JSON = "application/json";
    private static final String ACTION_BRANCHES = "branches";
    private static final String FIELD_COMPONENTS = "components";
    private static final String FIELD_METADATA = "metadata";
    private static final String FIELD_VULNERABILITIES = "vulnerabilities";
    private static final String NO_DEPENDENCY_SCAN_MESSAGE =
        "No dependency scan data is available for this project branch yet. Run an analysis with dependency scanning enabled, then refresh this page.";
    private static final String NOT_ANALYZED_MESSAGE =
        "This project has not been analyzed yet. Run a project analysis first, then refresh this page.";

    private final Configuration configuration;
    private final Path cacheDir;

    public SbomVisualizationWebService(Configuration configuration) {
        this.configuration = configuration;
        this.cacheDir = Paths.get(System.getProperty("java.io.tmpdir"), "sbomviz-cache");
        try {
            Files.createDirectories(cacheDir);
        } catch (IOException ignored) {
            // intentional
        }
    }

    @Override
    public void define(Context context) {
        registerController(context, "api/cdxsunshine");
        registerController(context, "api/sbomviz"); // alias for backward compatibility
    }

    private void registerController(Context context, String path) {
        NewController controller = context.createController(path);
        controller.setDescription("SBOM Visualization API");

        NewAction dataAction = controller.createAction("data")
            .setDescription("Get enriched SBOM data for a project")
            .setHandler(this::getData)
            .setInternal(true);
        dataAction.createParam(PARAM_PROJECT_KEY)
            .setRequired(true)
            .setDescription("The SonarQube project key");
        dataAction.createParam("branch")
            .setRequired(false)
            .setDescription("Branch name (defaults to main branch)");
        dataAction.createParam("noCache")
            .setRequired(false)
            .setDescription("Skip cache and force regeneration");

        NewAction branchesAction = controller.createAction(ACTION_BRANCHES)
            .setDescription("List branches for a project")
            .setHandler(this::getBranches)
            .setInternal(true);
        branchesAction.createParam(PARAM_PROJECT_KEY)
            .setRequired(true)
            .setDescription("The SonarQube project key");

        controller.done();
    }

    private void getBranches(Request request, Response response) throws Exception {
        String projectKey = request.mandatoryParam(PARAM_PROJECT_KEY);
        try {
            String branchesJson = callLocal(request, "api/project_branches/list",
                Map.of("project", projectKey), null);
            response.stream().setMediaType(APPLICATION_JSON);
            response.stream().output().write(branchesJson.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            writeJsonError(response, "Failed to fetch branches: " + e.getMessage());
        }
    }

    private void getData(Request request, Response response) throws Exception {
        String projectKey = request.mandatoryParam(PARAM_PROJECT_KEY);
        String branch = request.param("branch");
        boolean noCache = "true".equalsIgnoreCase(request.param("noCache"));

        Gson gson = new GsonBuilder().serializeNulls().create();

        try {
            if ((branch == null || branch.isBlank()) && !hasBranches(request, projectKey, gson)) {
                writeUnavailable(response, NOT_ANALYZED_MESSAGE, null);
                return;
            }

            // check last analysis date
            Instant lastAnalysis = fetchLastAnalysisDate(request, projectKey, branch, gson);

            // check cache (skip if noCache=true)
            Path cacheFile = cacheFile(projectKey, branch);
            Optional<String> cached = checkCache(cacheFile, lastAnalysis, noCache, gson);
            if (cached.isPresent()) {
                response.stream().setMediaType(APPLICATION_JSON);
                response.stream().output().write(addSettingsToResponse(cached.get(), gson).getBytes(StandardCharsets.UTF_8));
                return;
            }

            Optional<String> sbomJson = fetchSbomReport(request, projectKey, branch);
            if (sbomJson.isEmpty()) {
                writeUnavailable(response, NO_DEPENDENCY_SCAN_MESSAGE, lastAnalysis);
                return;
            }

            JsonObject sbom = gson.fromJson(sbomJson.get(), JsonObject.class);
            if (!isUsableCycloneDxSbom(sbom)) {
                writeUnavailable(response, NO_DEPENDENCY_SCAN_MESSAGE, lastAnalysis);
                return;
            }

            JsonArray risks = fetchRisks(request, projectKey, branch, gson);
            JsonObject enriched = mergeRisksIntoSbom(sbom, risks);

            String generatedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
            JsonObject result = new JsonObject();
            result.add("sbom", enriched);
            result.addProperty(GENERATED_AT, generatedAt);
            addLargeGraphLimits(result);
            if (lastAnalysis != null) {
                result.addProperty("lastAnalysisDate", DateTimeFormatter.ISO_INSTANT.format(lastAnalysis));
            }

            String resultJson = gson.toJson(result);

            // write to cache
            writeCacheFile(cacheFile, resultJson);

            response.stream().setMediaType(APPLICATION_JSON);
            response.stream().output().write(resultJson.getBytes(StandardCharsets.UTF_8));

        } catch (JsonParseException | IllegalStateException e) {
            writeJsonError(response, "Unexpected response from SonarQube SCA API: " + e.getMessage());
        } catch (IOException e) {
            writeJsonError(response, "Failed to fetch data from SonarQube API: " + e.getMessage());
        }
    }

    private Optional<String> fetchSbomReport(Request request, String projectKey, String branch) throws IOException {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("component", projectKey);
            params.put("type", "cyclonedx");
            addBranchParam(params, branch);
            return Optional.of(callLoopback(request, "api/v2/sca/sbom-reports", params, "application/vnd.cyclonedx+json"));
        } catch (IOException e) {
            if (isMissingScaData(e)) {
                return Optional.empty();
            }
            throw e;
        }
    }

    private String addSettingsToResponse(String json, Gson gson) {
        try {
            JsonObject obj = gson.fromJson(json, JsonObject.class);
            addLargeGraphLimits(obj);
            return gson.toJson(obj);
        } catch (Exception ignored) {
            return json;
        }
    }

    private void addLargeGraphLimits(JsonObject result) {
        JsonObject limits = new JsonObject();
        limits.addProperty("componentLimit", configuredPositiveInt(
            SbomVisualizationPlugin.COMPONENT_LIMIT_KEY,
            SbomVisualizationPlugin.COMPONENT_LIMIT_KEY_LEGACY,
            SbomVisualizationPlugin.DEFAULT_COMPONENT_LIMIT
        ));
        limits.addProperty("edgeLimit", configuredPositiveInt(
            SbomVisualizationPlugin.EDGE_LIMIT_KEY,
            SbomVisualizationPlugin.EDGE_LIMIT_KEY_LEGACY,
            SbomVisualizationPlugin.DEFAULT_EDGE_LIMIT
        ));
        result.add(LARGE_GRAPH_LIMITS, limits);
    }

    private int configuredPositiveInt(String primaryKey, String fallbackKey, int defaultValue) {
        Optional<Integer> primary = configuration.getInt(primaryKey);
        if (primary.isPresent() && primary.get() > 0) return primary.get();
        int value = configuration.getInt(fallbackKey).orElse(defaultValue);
        return value > 0 ? value : defaultValue;
    }

    private JsonArray fetchRisks(Request request, String projectKey, String branch, Gson gson) throws IOException {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("component", projectKey);
            addBranchParam(params, branch);
            String risksJson = callLoopback(request, "api/v2/sca/risk-reports", params, null);
            JsonElement risksEl = gson.fromJson(risksJson, JsonElement.class);
            if (risksEl == null || risksEl.isJsonNull()) {
                return new JsonArray();
            }
            if (risksEl.isJsonArray()) {
                return risksEl.getAsJsonArray();
            }
            if (risksEl.isJsonObject() && risksEl.getAsJsonObject().has("risks")) {
                JsonElement risks = risksEl.getAsJsonObject().get("risks");
                return risks.isJsonArray() ? risks.getAsJsonArray() : new JsonArray();
            }
            return new JsonArray();
        } catch (IOException e) {
            if (isMissingScaData(e)) {
                return new JsonArray();
            }
            throw e;
        }
    }

    private boolean hasBranches(Request request, String projectKey, Gson gson) {
        try {
            String branchesJson = callLocal(request, "api/project_branches/list",
                Map.of("project", projectKey), null);
            JsonObject obj = gson.fromJson(branchesJson, JsonObject.class);
            return obj.has(ACTION_BRANCHES)
                && obj.get(ACTION_BRANCHES).isJsonArray()
                && obj.getAsJsonArray(ACTION_BRANCHES).size() > 0;
        } catch (Exception ignored) {
            return true;
        }
    }

    private void addBranchParam(Map<String, String> params, String branch) {
        if (branch != null && !branch.isBlank()) {
            params.put("branch", branch);
        }
    }

    private boolean isUsableCycloneDxSbom(JsonObject sbom) {
        if (sbom == null) {
            return false;
        }
        boolean hasComponents = sbom.has(FIELD_COMPONENTS)
            && sbom.get(FIELD_COMPONENTS).isJsonArray()
            && sbom.getAsJsonArray(FIELD_COMPONENTS).size() > 0;
        boolean hasMetadataComponent = sbom.has(FIELD_METADATA)
            && sbom.get(FIELD_METADATA).isJsonObject()
            && sbom.getAsJsonObject(FIELD_METADATA).has("component");
        return hasComponents || hasMetadataComponent;
    }

    private boolean isMissingScaData(IOException e) {
        String message = e.getMessage();
        return message != null && (message.contains("Not found (404)") || message.contains("HTTP 204"));
    }

    // S3776 — extracted from getData to reduce cognitive complexity
    private Optional<String> checkCache(Path cacheFile, Instant lastAnalysis, boolean noCache, Gson gson) {
        if (noCache || lastAnalysis == null || !Files.exists(cacheFile)) {
            return Optional.empty();
        }
        return readFromCache(cacheFile, gson, lastAnalysis);
    }

    // S1141 — extracted inner try block from getData
    private Optional<String> readFromCache(Path cacheFile, Gson gson, Instant lastAnalysis) {
        try {
            String cached = new String(Files.readAllBytes(cacheFile), StandardCharsets.UTF_8);
            JsonObject cachedObj = gson.fromJson(cached, JsonObject.class);
            if (cachedObj.has(GENERATED_AT)) {
                Instant cachedAt = Instant.parse(cachedObj.get(GENERATED_AT).getAsString());
                if (!cachedAt.isBefore(lastAnalysis)) {
                    // cache is fresh
                    return Optional.of(cached);
                }
            }
        } catch (Exception ignored) {
            // corrupt cache — fall through to refresh
        }
        return Optional.empty();
    }

    // S1141 — extracted cache-write try block from getData
    private void writeCacheFile(Path cacheFile, String content) {
        try {
            Files.write(cacheFile, content.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // intentional
        }
    }

    private Instant fetchLastAnalysisDate(Request request, String projectKey, String branch, Gson gson) {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("project", projectKey);
            params.put("ps", "1");
            addBranchParam(params, branch);
            String json = callLocal(request, "api/project_analyses/search", params, null);
            JsonObject obj = gson.fromJson(json, JsonObject.class);
            if (obj.has("analyses")) {
                JsonArray analyses = obj.getAsJsonArray("analyses");
                if (analyses.size() > 0) {
                    String date = analyses.get(0).getAsJsonObject().get("date").getAsString();
                    // SQ returns "+0000" (no colon); try ISO first, then pattern-based fallback
                    Instant parsed = parseInstant(date);
                    if (parsed != null) {
                        return parsed;
                    }
                    return OffsetDateTime.parse(date,
                        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ")).toInstant();
                }
            }
        } catch (Exception ignored) {
            // intentional
        }
        return null;
    }

    // S1141 — extracted inner try from fetchLastAnalysisDate
    private Instant parseInstant(String date) {
        try {
            return Instant.from(DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(date));
        } catch (Exception ignored) {
            // intentional — fall through to pattern-based fallback in caller
        }
        return null;
    }

    private Path cacheFile(String projectKey, String branch) {
        String safeName = (projectKey + "_" + (branch != null ? branch : "default"))
            .replaceAll("[^a-zA-Z0-9._-]", "_");
        return cacheDir.resolve(safeName + ".json");
    }

    private void writeJsonError(Response response, String message) throws IOException {
        JsonObject err = new JsonObject();
        err.addProperty("error", message);
        response.stream().setMediaType(APPLICATION_JSON);
        response.stream().output().write(new Gson().toJson(err).getBytes(StandardCharsets.UTF_8));
    }

    private void writeUnavailable(Response response, String message, Instant lastAnalysis) throws IOException {
        JsonObject unavailable = new JsonObject();
        unavailable.addProperty("unavailable", true);
        unavailable.addProperty("message", message);
        if (lastAnalysis != null) {
            unavailable.addProperty("lastAnalysisDate", DateTimeFormatter.ISO_INSTANT.format(lastAnalysis));
        }
        response.stream().setMediaType(APPLICATION_JSON);
        response.stream().output().write(new Gson().toJson(unavailable).getBytes(StandardCharsets.UTF_8));
    }

    // in-process call via LocalConnector — propagates the caller's own session/permissions, no token
    private String callLocal(Request request, String path, Map<String, String> params, String mediaType) throws IOException {
        LocalConnector.LocalResponse resp = request.localConnector().call(
            new SimpleLocalRequest(path, mediaType, params));

        int code = resp.getStatus();
        if (code == 401) throw new IOException("Authentication failed (401) calling " + path + ".");
        if (code == 403) throw new IOException("Access forbidden (403). You lack the required permissions for this project.");
        if (code == 404) throw new IOException("Not found (404). Project may not have an SBOM. Ensure SCA is enabled and the project has been analyzed.");
        if (code != 200) throw new IOException("HTTP " + code + " from SonarQube API at " + path);

        return new String(resp.getBytes(), StandardCharsets.UTF_8);
    }

    private static final class SimpleLocalRequest implements LocalConnector.LocalRequest {
        private final String path;
        private final String mediaType;
        private final Map<String, String> params;

        SimpleLocalRequest(String path, String mediaType, Map<String, String> params) {
            this.path = path;
            this.mediaType = mediaType;
            this.params = params;
        }

        @Override
        public String getPath() {
            return path;
        }

        @Override
        public String getMediaType() {
            return mediaType;
        }

        @Override
        public String getMethod() {
            return "GET";
        }

        @Override
        public boolean hasParam(String key) {
            return params.containsKey(key);
        }

        @Override
        public String getParam(String key) {
            return params.get(key);
        }

        @Override
        public List<String> getMultiParam(String key) {
            return params.containsKey(key) ? List.of(params.get(key)) : Collections.emptyList();
        }

        @Override
        public Optional<String> getHeader(String name) {
            return Optional.empty();
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> map = new HashMap<>();
            params.forEach((k, v) -> map.put(k, new String[]{v}));
            return map;
        }
    }

    private String baseUrl() {
        int port = configuration.getInt("sonar.web.port").orElse(9000);
        String ctx = configuration.get("sonar.web.context").orElse("").replaceAll("/$", "");
        return "http://localhost:" + port + ctx;
    }

    // api/v2/* endpoints don't dispatch through LocalConnector (confirmed 404 — it only
    // reaches classic v1 WebService actions), so these fall back to a loopback HTTP call —
    // authenticated by forwarding the caller's own Cookie/Authorization header, not a token.
    private String callLoopback(Request request, String path, Map<String, String> params, String accept) throws IOException {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (query.length() > 0) query.append('&');
            query.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                .append('=')
                .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        URL url = new URL(baseUrl() + "/" + path + "?" + query);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(30_000);
        conn.setReadTimeout(120_000);
        conn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
        request.header("Cookie").ifPresent(v -> conn.setRequestProperty("Cookie", v));
        request.header("Authorization").ifPresent(v -> conn.setRequestProperty("Authorization", v));
        if (accept != null) {
            conn.setRequestProperty("Accept", accept);
        }

        int code = conn.getResponseCode();
        if (code == 401) throw new IOException("Authentication failed (401) calling " + path + ".");
        if (code == 403) throw new IOException("Access forbidden (403). You lack the required permissions for this project.");
        if (code == 404) throw new IOException("Not found (404). Project may not have an SBOM. Ensure SCA is enabled and the project has been analyzed.");
        if (code != 200) throw new IOException("HTTP " + code + " from SonarQube API at " + path);

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
            if (el.isJsonObject()) {
                final JsonObject risk = el.getAsJsonObject();
                if (risk.has("packageUrl")) {
                    final String purl = risk.get("packageUrl").getAsString();
                    risksMap.computeIfAbsent(purl, k -> new JsonArray()).add(risk);
                }
            }
        }

        if (sbom.has(FIELD_COMPONENTS)) {
            for (JsonElement el : sbom.getAsJsonArray(FIELD_COMPONENTS)) {
                if (!el.isJsonObject()) continue;
                JsonObject comp = el.getAsJsonObject();
                applyRisksToComponent(comp, risksMap);
            }
        }
        return sbom;
    }

    // S3776 — extracted from mergeRisksIntoSbom inner loop to reduce cognitive complexity
    private void applyRisksToComponent(JsonObject comp, Map<String, JsonArray> risksMap) {
        if (!comp.has("purl")) return;
        String purl = comp.get("purl").getAsString();
        JsonArray matching = risksMap.get(purl);
        if (matching == null) return;

        if (!comp.has(FIELD_VULNERABILITIES)) {
            comp.add(FIELD_VULNERABILITIES, new JsonArray());
        }
        JsonArray vulns = comp.getAsJsonArray(FIELD_VULNERABILITIES);
        for (JsonElement riskEl : matching) {
            vulns.add(formatVulnerability(riskEl.getAsJsonObject()));
        }
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

        // S3776 — CWE parsing extracted to parseCwes
        if (risk.has("cweIds")) {
            JsonArray cwes = parseCwes(risk);
            if (cwes.size() > 0) vuln.add("cwes", cwes);
        }
        if (risk.has("riskTitle")) vuln.addProperty("description", risk.get("riskTitle").getAsString());
        return vuln;
    }

    // S3776 — extracted CWE parsing from formatVulnerability
    private JsonArray parseCwes(JsonObject risk) {
        JsonArray cwes = new JsonArray();
        for (JsonElement cweEl : risk.getAsJsonArray("cweIds")) {
            String cwe = cweEl.getAsString();
            if (cwe.contains("-")) {
                try {
                    cwes.add(Integer.parseInt(cwe.split("-")[1]));
                } catch (NumberFormatException ignored) {
                    // intentional
                }
            }
        }
        return cwes;
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
