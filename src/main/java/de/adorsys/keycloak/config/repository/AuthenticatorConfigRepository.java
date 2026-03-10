/*-
 * ---license-start
 * keycloak-config-cli
 * ---
 * Copyright (C) 2017 - 2021 adorsys GmbH & Co. KG @ https://adorsys.com
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package de.adorsys.keycloak.config.repository;

import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
@ConditionalOnProperty(prefix = "run", name = "operation", havingValue = "IMPORT", matchIfMissing = true)
public class AuthenticatorConfigRepository {

    private final AuthenticationFlowRepository authenticationFlowRepository;
    private final RealmRepository realmRepository;

    @Autowired
    public AuthenticatorConfigRepository(
            AuthenticationFlowRepository authenticationFlowRepository,
            RealmRepository realmRepository
    ) {
        this.authenticationFlowRepository = authenticationFlowRepository;
        this.realmRepository = realmRepository;
    }

    public List<AuthenticatorConfigRepresentation> getConfigsByAlias(String realmName, String alias) {
        RealmRepresentation realmExport = realmRepository.partialExport(realmName, false, false);
        return realmExport.getAuthenticatorConfig()
                .stream()
                .filter(config -> Objects.equals(config.getAlias(), alias))
                .toList();
    }

    public AuthenticatorConfigRepresentation getConfigByAlias(String realmName, String alias) {
        RealmRepresentation realmExport = realmRepository.partialExport(realmName, false, false);
        return realmExport.getAuthenticatorConfig()
                .stream()
                .filter(config -> Objects.equals(config.getAlias(), alias))
                .findFirst()
                .orElse(null);
    }

    public void delete(String realmName, String id) {
        AuthenticationManagementResource flowsResource = authenticationFlowRepository.getFlowResources(realmName);
        flowsResource.removeAuthenticatorConfig(id);
    }

    public void create(
            String realmName,
            String executionId,
            AuthenticatorConfigRepresentation authenticatorConfigRepresentation
    ) {
        AuthenticationManagementResource flowsResource = authenticationFlowRepository.getFlowResources(realmName);
        flowsResource.newExecutionConfig(executionId, authenticatorConfigRepresentation);
    }

    public void update(
            String realmName,
            AuthenticatorConfigRepresentation authenticatorConfigRepresentation
    ) {
        AuthenticationManagementResource flowsResource = authenticationFlowRepository.getFlowResources(realmName);
        flowsResource.updateAuthenticatorConfig(
                authenticatorConfigRepresentation.getId(),
                authenticatorConfigRepresentation
        );
    }

    public List<AuthenticatorConfigRepresentation> getAll(String realmName) {
        RealmRepresentation realmExport = realmRepository.partialExport(realmName, false, false);
        return realmExport.getAuthenticatorConfig();
    }

    public boolean exists(String realmName, String alias, String executionId) {
        // Check if the specific execution already has ANY authenticator config
        // We don't care about the alias here since multiple executions can share the same config alias
        // but each execution needs its own config instance
        return hasExecutionConfig(realmName, executionId);
    }

    /**
     * Check if an execution already has an authenticator config associated with it.
     */
    private boolean hasExecutionConfig(String realmName, String executionId) {
        AuthenticationManagementResource flowsResource = authenticationFlowRepository.getFlowResources(realmName);

        // Get all flows and check each one's executions
        for (AuthenticationFlowRepresentation flow : authenticationFlowRepository.getAll(realmName)) {
            List<AuthenticationExecutionInfoRepresentation> executions = flowsResource.getExecutions(flow.getAlias());
            for (AuthenticationExecutionInfoRepresentation execution : executions) {
                if (Objects.equals(execution.getId(), executionId)) {
                    return execution.getAuthenticationConfig() != null;
                }
            }
        }
        return false;
    }
}
