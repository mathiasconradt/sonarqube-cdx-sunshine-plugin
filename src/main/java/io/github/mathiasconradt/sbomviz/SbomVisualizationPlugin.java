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

import org.sonar.api.Plugin;
import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;

public class SbomVisualizationPlugin implements Plugin {
    static final String SETTINGS_CATEGORY = "SBOM Visualization";
    static final String TOKEN_KEY = "sbomviz.sonar.token";
    static final String COMPONENT_LIMIT_KEY = "sbomviz.largeGraph.componentLimit";
    static final String EDGE_LIMIT_KEY = "sbomviz.largeGraph.edgeLimit";
    static final int DEFAULT_COMPONENT_LIMIT = 5000;
    static final int DEFAULT_EDGE_LIMIT = 15000;

    @Override
    public void define(Context context) {
        context.addExtensions(
            PropertyDefinition.builder(TOKEN_KEY)
                .name("SonarQube Token")
                .description("Token with permission to read project SBOM and SCA data. " +
                    "Stored as a global setting and used by the plugin to call the SonarQube SCA API on behalf of users.")
                .category(SETTINGS_CATEGORY)
                .subCategory("Authentication")
                .index(1)
                .type(PropertyType.PASSWORD)
                .build(),
            PropertyDefinition.builder(COMPONENT_LIMIT_KEY)
                .name("Component limit")
                .description("Maximum number of unique SBOM components before the dependency sunburst chart is disabled and the project page switches to table-only mode. " +
                    "The chart is rendered as a sunburst — for very large dependency graphs it can exceed browser memory because dependency paths are expanded into chart nodes. " +
                    "Default: " + DEFAULT_COMPONENT_LIMIT + ".")
                .category(SETTINGS_CATEGORY)
                .subCategory("Large Project Mode")
                .index(1)
                .type(PropertyType.INTEGER)
                .defaultValue(String.valueOf(DEFAULT_COMPONENT_LIMIT))
                .build(),
            PropertyDefinition.builder(EDGE_LIMIT_KEY)
                .name("Dependency relationship limit")
                .description("Maximum number of dependency relationships before the dependency sunburst chart is disabled and the project page switches to table-only mode. " +
                    "Default: " + DEFAULT_EDGE_LIMIT + ".")
                .category(SETTINGS_CATEGORY)
                .subCategory("Large Project Mode")
                .index(2)
                .type(PropertyType.INTEGER)
                .defaultValue(String.valueOf(DEFAULT_EDGE_LIMIT))
                .build(),
            SbomVisualizationPageDefinition.class,
            SbomVisualizationWebService.class
        );
    }
}
