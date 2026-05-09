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
                .description("Token used by the SBOM Visualization plugin to read project SBOM and SCA data.")
                .category(SETTINGS_CATEGORY)
                .type(PropertyType.PASSWORD)
                .build(),
            PropertyDefinition.builder(COMPONENT_LIMIT_KEY)
                .name("Large graph component limit")
                .description("Maximum number of SBOM components for which the dependency sunburst chart is rendered. Larger projects use table-only mode.")
                .category(SETTINGS_CATEGORY)
                .type(PropertyType.INTEGER)
                .defaultValue(String.valueOf(DEFAULT_COMPONENT_LIMIT))
                .build(),
            PropertyDefinition.builder(EDGE_LIMIT_KEY)
                .name("Large graph dependency relationship limit")
                .description("Maximum number of dependency relationships for which the dependency sunburst chart is rendered. Larger graphs use table-only mode.")
                .category(SETTINGS_CATEGORY)
                .type(PropertyType.INTEGER)
                .defaultValue(String.valueOf(DEFAULT_EDGE_LIMIT))
                .build(),
            SbomVisualizationPageDefinition.class,
            SbomVisualizationWebService.class
        );
    }
}
