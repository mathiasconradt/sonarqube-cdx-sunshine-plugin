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

import org.sonar.api.web.page.Context;
import org.sonar.api.web.page.Page;
import org.sonar.api.web.page.PageDefinition;

public class SbomVisualizationPageDefinition implements PageDefinition {
    @Override
    public void define(Context context) {
        context.addPage(Page.builder("sbomviz/admin")
            .setName("SBOM Visualization")
            .setScope(Page.Scope.GLOBAL)
            .setAdmin(true)
            .build());

        context.addPage(Page.builder("sbomviz/project")
            .setName("SBOM Visualization")
            .setScope(Page.Scope.COMPONENT)
            .build());
    }
}
