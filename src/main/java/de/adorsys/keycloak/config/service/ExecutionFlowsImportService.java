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

package de.adorsys.keycloak.config.service;

import de.adorsys.keycloak.config.exception.ImportProcessingException;
import de.adorsys.keycloak.config.exception.InvalidImportException;
import de.adorsys.keycloak.config.model.RealmImport;
import de.adorsys.keycloak.config.repository.AuthenticationFlowRepository;
import de.adorsys.keycloak.config.repository.AuthenticatorConfigRepository;
import de.adorsys.keycloak.config.repository.ExecutionFlowRepository;
import de.adorsys.keycloak.config.util.AuthenticationFlowUtil;
import de.adorsys.keycloak.config.util.ResponseUtil;
import org.keycloak.representations.idm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import jakarta.ws.rs.WebApplicationException;

/**
 * Imports executions and execution-flows of existing top-level flows
 */
@Service
@ConditionalOnProperty(prefix = "run", name = "operation", havingValue = "IMPORT", matchIfMissing = true)
public class ExecutionFlowsImportService {
    private static final Logger logger = LoggerFactory.getLogger(ExecutionFlowsImportService.class);

    private final ExecutionFlowRepository executionFlowRepository;
    private final AuthenticatorConfigRepository authenticatorConfigRepository;
    private final AuthenticationFlowRepository authenticationFlowRepository;

    /**
     * Caches authenticatorConfig IDs by alias for the duration of one import run.
     * This avoids relying on realm partial export returning authenticator configs
     * (which may differ between Keycloak versions) and prevents duplicate creation
     * attempts for the same alias.
     */
    private final Map<String, String> authenticatorConfigIdsByAlias = new HashMap<>();

    @Autowired
    public ExecutionFlowsImportService(
            ExecutionFlowRepository executionFlowRepository,
            AuthenticatorConfigRepository authenticatorConfigRepository,
            AuthenticationFlowRepository authenticationFlowRepository) {
        this.executionFlowRepository = executionFlowRepository;
        this.authenticatorConfigRepository = authenticatorConfigRepository;
        this.authenticationFlowRepository = authenticationFlowRepository;
    }

    private void attachExecutionConfigViaEndpoint(
            RealmImport realmImport,
            String authenticatorConfigName,
            String flowAlias,
            String executionId,
            boolean forceUniqueAlias) {
        // Create a new execution config instance with the same alias+config.
        // Note: Keycloak does not persist attaching an existing config id via
        // updateExecutions()
        // and newExecutionConfig() creates a config for the given execution.
        AuthenticatorConfigRepresentation definition = Optional
                .ofNullable(realmImport.getAuthenticatorConfig())
                .orElse(List.of())
                .stream()
                .filter(x -> Objects.equals(x.getAlias(), authenticatorConfigName))
                .findAny()
                .orElseThrow(() -> new ImportProcessingException(
                        String.format(
                                "Authenticator config '%s' definition not found",
                                authenticatorConfigName)));

        AuthenticatorConfigRepresentation configToCreate = new AuthenticatorConfigRepresentation();
        if (forceUniqueAlias) {
            configToCreate.setAlias(authenticatorConfigName + "-" + executionId);
        } else {
            configToCreate.setAlias(definition.getAlias());
        }
        configToCreate.setConfig(definition.getConfig());

        logger.debug("Creating authenticator config '{}' for execution '{}'", authenticatorConfigName,
                executionId);

        try {
            authenticatorConfigRepository.create(realmImport.getRealm(), executionId, configToCreate);
        } catch (WebApplicationException error) {
            logger.debug(
                    "Could not create authenticator config '{}' for execution '{}' in flow '{}' (will retry with a unique alias): {}",
                    authenticatorConfigName,
                    executionId,
                    flowAlias,
                    ResponseUtil.getErrorMessage(error));

            AuthenticatorConfigRepresentation uniqueConfigToCreate = new AuthenticatorConfigRepresentation();
            uniqueConfigToCreate.setAlias(authenticatorConfigName + "-" + executionId);
            uniqueConfigToCreate.setConfig(definition.getConfig());
            authenticatorConfigRepository.create(realmImport.getRealm(), executionId, uniqueConfigToCreate);
        }
    }

    public void createExecutionsAndExecutionFlows(
            RealmImport realmImport,
            AuthenticationFlowRepresentation topLevelFlowToImport,
            AuthenticationFlowRepresentation existingTopLevelFlow) {
        for (AuthenticationExecutionExportRepresentation executionToImport : topLevelFlowToImport
                .getAuthenticationExecutions()) {
            createExecutionOrExecutionFlow(realmImport, topLevelFlowToImport, existingTopLevelFlow,
                    executionToImport);
        }
    }

    public void updateExecutionFlows(
            RealmImport realmImport,
            AuthenticationFlowRepresentation flowToImport) {
        for (AuthenticationExecutionExportRepresentation execution : flowToImport
                .getAuthenticationExecutions()) {
            configureExecutionFlow(realmImport, flowToImport, execution);
        }
    }

    @SuppressWarnings("deprecation")
    private void createExecutionOrExecutionFlow(
            RealmImport realmImport,
            AuthenticationFlowRepresentation topLevelFlowToImport,
            AuthenticationFlowRepresentation existingTopLevelFlow,
            AuthenticationExecutionExportRepresentation executionOrExecutionFlowToImport) {
        if (executionOrExecutionFlowToImport.isAutheticatorFlow()) {
            createAndConfigureExecutionFlow(realmImport, topLevelFlowToImport,
                    executionOrExecutionFlowToImport);
        } else {
            createExecutionForTopLevelFlow(realmImport, existingTopLevelFlow,
                    executionOrExecutionFlowToImport);
        }
    }

    private void createAndConfigureExecutionFlow(
            RealmImport realmImport,
            AuthenticationFlowRepresentation topLevelFlowToImport,
            AuthenticationExecutionExportRepresentation executionFlowToImport) {
        AuthenticationFlowRepresentation subFlowToImport = AuthenticationFlowUtil
                .getSubFlow(realmImport, executionFlowToImport.getFlowAlias());

        createSubFlowByExecutionFlow(realmImport, topLevelFlowToImport, executionFlowToImport, subFlowToImport);
        configureExecutionFlow(realmImport, topLevelFlowToImport, executionFlowToImport);

        createExecutionAndExecutionFlowsForSubFlows(realmImport, subFlowToImport);
    }

    @SuppressWarnings("deprecation")
    private void createExecutionForTopLevelFlow(
            RealmImport realmImport,
            AuthenticationFlowRepresentation existingTopLevelFlow,
            AuthenticationExecutionExportRepresentation executionToImport) {
        logger.debug("Creating execution '{}' for top-level-flow: '{}' in realm '{}'",
                executionToImport.getAuthenticator(), existingTopLevelFlow.getAlias(),
                realmImport.getRealm());

        AuthenticationExecutionRepresentation executionToCreate = new AuthenticationExecutionRepresentation();

        executionToCreate.setParentFlow(existingTopLevelFlow.getId());
        executionToCreate.setAuthenticator(executionToImport.getAuthenticator());
        executionToCreate.setRequirement(executionToImport.getRequirement());
        executionToCreate.setPriority(executionToImport.getPriority());
        executionToCreate.setAutheticatorFlow(false);

        String executionId = executionFlowRepository.createTopLevelFlowExecution(realmImport.getRealm(),
                executionToCreate);

        if (executionToImport.getAuthenticatorConfig() != null) {
            attachAuthenticatorConfigToExecution(
                    realmImport,
                    executionToImport.getAuthenticatorConfig(),
                    existingTopLevelFlow.getAlias(),
                    executionId);
        }
    }

    /**
     * Creates the executionFlow within the topLevel-flow AND creates the
     * non-topLevel flow because keycloak does
     * this automatically while calling `flowsResource.addExecutionFlow`
     */
    private void createSubFlowByExecutionFlow(
            RealmImport realmImport,
            AuthenticationFlowRepresentation topLevelFlowToImport,
            AuthenticationExecutionExportRepresentation executionToImport,
            AuthenticationFlowRepresentation subFlow) {
        logger.debug("Creating non-top-level-flow '{}' for top-level-flow '{}' by its execution '{}' in realm '{}'",
                subFlow.getAlias(), topLevelFlowToImport.getAlias(),
                executionToImport.getFlowAlias(), realmImport.getRealm());

        if (!Objects.equals(executionToImport.getAuthenticator(), null)
                && !Objects.equals(subFlow.getProviderId(), "form-flow")) {
            throw new InvalidImportException(String.format(
                    "Execution property authenticator '%s' can be only set if the sub-flow '%s' type is 'form-flow'.",
                    executionToImport.getAuthenticator(), subFlow.getAlias()));
        }

        HashMap<String, String> executionFlow = new HashMap<>();
        executionFlow.put("alias", executionToImport.getFlowAlias());
        executionFlow.put("provider", executionToImport.getAuthenticator());
        executionFlow.put("type", subFlow.getProviderId());
        executionFlow.put("description", subFlow.getDescription());
        executionFlow.put("authenticator", subFlow.getProviderId());

        try {
            executionFlowRepository.createExecutionFlow(realmImport.getRealm(),
                    topLevelFlowToImport.getAlias(), executionFlow);
        } catch (WebApplicationException error) {
            String errorMessage = ResponseUtil.getErrorMessage(error);
            throw new ImportProcessingException(
                    String.format(
                            "Cannot create execution-flow '%s' for top-level-flow '%s' in realm '%s': %s",
                            executionToImport.getFlowAlias(),
                            topLevelFlowToImport.getAlias(),
                            realmImport.getRealm(), errorMessage),
                    error);
        }
    }

    /**
     * We have to re-configure the requirement property separately as long as
     * keycloak is only allowing to set the 'provider'
     * and is ignoring the value and sets the requirement hardcoded to DISABLED
     * while creating execution-flow.
     *
     * @see #createExecutionForSubFlow
     */
    private void configureExecutionFlow(
            RealmImport realmImport,
            AuthenticationFlowRepresentation topLevelOrSubFlowToImport,
            AuthenticationExecutionExportRepresentation executionToImport) {
        debugLogExecutionFlowCreation(realmImport, topLevelOrSubFlowToImport.getAlias(), executionToImport);

        List<AuthenticationExecutionInfoRepresentation> storedExecutionFlows = executionFlowRepository
                .getExecutionFlowsByAlias(
                        realmImport.getRealm(), topLevelOrSubFlowToImport.getAlias(),
                        executionToImport);

        if (storedExecutionFlows.size() != 1) {
            throw new ImportProcessingException(String.format(
                    "Unexpected size of execution %s in flow %s found.",
                    executionToImport.getAuthenticator(), topLevelOrSubFlowToImport.getAlias()));
        }

        AuthenticationExecutionInfoRepresentation storedExecutionFlow = storedExecutionFlows.get(0);
        storedExecutionFlow.setRequirement(executionToImport.getRequirement());

        if (executionToImport.getAuthenticatorConfig() != null) {
            String configId = getOrCreateRealmAuthenticatorConfigId(
                    realmImport,
                    executionToImport.getAuthenticatorConfig(),
                    topLevelOrSubFlowToImport.getAlias(),
                    storedExecutionFlow.getId());
            storedExecutionFlow.setAuthenticationConfig(configId);
        }

        try {
            executionFlowRepository.updateExecutionFlow(
                    realmImport.getRealm(),
                    topLevelOrSubFlowToImport.getAlias(),
                    storedExecutionFlow);
        } catch (WebApplicationException error) {
            String errorMessage = ResponseUtil.getErrorMessage(error);
            throw new ImportProcessingException(
                    String.format(
                            "Cannot update execution-flow '%s' for flow '%s' in realm '%s': %s",
                            executionToImport.getAuthenticator(),
                            topLevelOrSubFlowToImport.getAlias(),
                            realmImport.getRealm(), errorMessage),
                    error);
        }

        // Authenticator config is attached via execution update above (UI-like
        // behavior)
    }

    @SuppressWarnings("deprecation")
    private void createExecutionAndExecutionFlowsForSubFlows(
            RealmImport realmImport,
            AuthenticationFlowRepresentation subFlow) {
        for (AuthenticationExecutionExportRepresentation executionOrExecutionFlowToImport : subFlow
                .getAuthenticationExecutions()) {

            if (executionOrExecutionFlowToImport.isAutheticatorFlow()) {
                createAndConfigureExecutionFlow(realmImport, subFlow, executionOrExecutionFlowToImport);
            } else {
                createExecutionForSubFlow(realmImport, subFlow, executionOrExecutionFlowToImport);
                configureExecutionFlow(realmImport, subFlow, executionOrExecutionFlowToImport);
            }
        }
    }

    /**
     * Keycloak is only allowing to set the 'provider' property while creating an
     * execution. The other properties have
     * to be set afterwards with an update.
     *
     * @see #configureExecutionFlow
     */
    private void createExecutionForSubFlow(
            RealmImport realmImport,
            AuthenticationFlowRepresentation subFlow,
            AuthenticationExecutionExportRepresentation executionToImport) {
        logger.debug("Create execution '{}' for non-top-level-flow '{}' in realm '{}'",
                executionToImport.getAuthenticator(), subFlow.getAlias(), realmImport.getRealm());

        HashMap<String, String> execution = new HashMap<>();
        execution.put("provider", executionToImport.getAuthenticator());

        try {
            executionFlowRepository.createSubFlowExecution(realmImport.getRealm(), subFlow.getAlias(),
                    execution);
        } catch (WebApplicationException error) {
            String errorMessage = ResponseUtil.getErrorMessage(error);
            throw new ImportProcessingException(
                    String.format(
                            "Cannot create execution '%s' for non-top-level-flow '%s' in realm '%s': %s",
                            executionToImport.getAuthenticator(), subFlow.getAlias(),
                            realmImport.getRealm(), errorMessage),
                    error);
        }

        if (executionToImport.getAuthenticatorConfig() != null) {
            List<AuthenticationExecutionInfoRepresentation> executionFlows = executionFlowRepository
                    .getExecutionFlowsByAlias(
                            realmImport.getRealm(),
                            subFlow.getAlias(),
                            executionToImport)
                    .stream()
                    .filter(flow -> flow.getAuthenticationConfig() == null)
                    .toList();

            if (executionFlows.size() != 1) {
                throw new ImportProcessingException(
                        String.format(
                                "Unexpected size of execution %s in flow %s. Expected: 1. Actual: %d",
                                executionToImport.getAuthenticator(),
                                subFlow.getAlias(), executionFlows.size()));
            }

            attachAuthenticatorConfigToExecution(
                    realmImport,
                    executionToImport.getAuthenticatorConfig(),
                    subFlow.getAlias(),
                    executionFlows.get(0).getId());
        }
    }

    private void attachAuthenticatorConfigToExecution(
            RealmImport realmImport,
            String authenticatorConfigName,
            String flowAlias,
            String executionId) {
        String configId = getOrCreateRealmAuthenticatorConfigId(realmImport, authenticatorConfigName, flowAlias,
                executionId);

        List<AuthenticationExecutionInfoRepresentation> executions = executionFlowRepository
                .getExecutionsByAuthFlow(realmImport.getRealm(), flowAlias);

        AuthenticationExecutionInfoRepresentation executionToUpdate = executions
                .stream()
                .filter(e -> Objects.equals(e.getId(), executionId))
                .findFirst()
                .orElseThrow(() -> new ImportProcessingException(
                        String.format(
                                "Cannot find execution '%s' in flow '%s' in realm '%s'",
                                executionId,
                                flowAlias,
                                realmImport.getRealm())));

        // If the execution currently has no config, try to link the found/created
        // config id.
        if (executionToUpdate.getAuthenticationConfig() == null) {
            executionToUpdate.setAuthenticationConfig(configId);

            try {
                logger.debug("Linking existing authenticator config '{}' (id: {}) to execution '{}' in flow '{}'",
                        authenticatorConfigName, configId, executionId, flowAlias);
                executionFlowRepository.updateExecutionFlow(realmImport.getRealm(), flowAlias,
                        executionToUpdate);
            } catch (WebApplicationException error) {
                logger.debug(
                        "Failed to link authenticator config '{}' to execution '{}' via updateExecutions, falling back to dedicated endpoint: {}",
                        authenticatorConfigName, executionId,
                        ResponseUtil.getErrorMessage(error));

                // Fall back to the dedicated endpoint if direct linking fails.
                // This will try to create the config, which might trigger the unique-alias
                // retry logic
                // if the config already exists but linking failed for some reason.
                attachExecutionConfigViaEndpoint(realmImport, authenticatorConfigName, flowAlias,
                        executionId, false);
            }

            // Verify if the config was successfully attached (either via update or
            // endpoint)
            AuthenticationExecutionInfoRepresentation reloaded = null;
            for (int attempt = 0; attempt < 60; attempt++) {
                List<AuthenticationExecutionInfoRepresentation> reloadedExecutions = executionFlowRepository
                        .getExecutionsByAuthFlow(realmImport.getRealm(), flowAlias);
                reloaded = reloadedExecutions.stream()
                        .filter(e -> Objects.equals(e.getId(), executionId))
                        .findFirst()
                        .orElse(null);

                if (reloaded != null && reloaded.getAuthenticationConfig() != null) {
                    logger.debug(
                            "Execution '{}' in flow '{}' persisted authenticator config id '{}'",
                            executionId,
                            flowAlias,
                            reloaded.getAuthenticationConfig());
                    return;
                }

                try {
                    Thread.sleep(250L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // One last retry with a unique alias if it still didn't persist
            if (reloaded == null || reloaded.getAuthenticationConfig() == null) {
                attachExecutionConfigViaEndpoint(realmImport, authenticatorConfigName, flowAlias,
                        executionId, true);
                for (int attempt = 0; attempt < 60; attempt++) {
                    List<AuthenticationExecutionInfoRepresentation> reloadedExecutions = executionFlowRepository
                            .getExecutionsByAuthFlow(realmImport.getRealm(), flowAlias);
                    reloaded = reloadedExecutions.stream()
                            .filter(e -> Objects.equals(e.getId(), executionId))
                            .findFirst()
                            .orElse(null);

                    if (reloaded != null && reloaded.getAuthenticationConfig() != null) {
                        logger.debug(
                                "Execution '{}' in flow '{}' persisted authenticator config id '{}' after retry with unique alias",
                                executionId,
                                flowAlias,
                                reloaded.getAuthenticationConfig());
                        return;
                    }

                    try {
                        Thread.sleep(250L);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            if (reloaded == null || reloaded.getAuthenticationConfig() == null) {
                throw new ImportProcessingException(String.format(
                        "Keycloak did not persist authenticator config '%s' for execution '%s' in flow '%s' in realm '%s'",
                        authenticatorConfigName,
                        executionId,
                        flowAlias,
                        realmImport.getRealm()));
            }
            return;
        }

        if (Objects.equals(executionToUpdate.getAuthenticationConfig(), configId)) {
            logger.debug("Execution '{}' already references authenticator config '{}', skipping",
                    executionId, configId);
            return;
        }

        executionToUpdate.setAuthenticationConfig(configId);

        try {
            executionFlowRepository.updateExecutionFlow(realmImport.getRealm(), flowAlias,
                    executionToUpdate);
        } catch (WebApplicationException error) {
            String errorMessage = ResponseUtil.getErrorMessage(error);
            throw new ImportProcessingException(
                    String.format(
                            "Cannot attach authenticator config '%s' to execution '%s' in flow '%s' in realm '%s': %s",
                            authenticatorConfigName,
                            executionId,
                            flowAlias,
                            realmImport.getRealm(),
                            errorMessage),
                    error);
        }
    }

    private String getOrCreateRealmAuthenticatorConfigId(
            RealmImport realmImport,
            String authenticatorConfigName,
            String flowAliasForExecutionLookup,
            String executionIdForCreation) {
        String cached = authenticatorConfigIdsByAlias.get(authenticatorConfigName);
        if (cached != null) {
            return cached;
        }

        List<AuthenticatorConfigRepresentation> existing = authenticatorConfigRepository
                .getConfigsByAlias(realmImport.getRealm(), authenticatorConfigName);

        if (!existing.isEmpty()) {
            String id = existing.get(0).getId();
            authenticatorConfigIdsByAlias.put(authenticatorConfigName, id);
            return id;
        }

        // If not found in existing configs, try to find it by inspecting the execution
        // itself
        // (This handles cases where the config might be newly created but not yet
        // visible in partial export)
        List<AuthenticationExecutionInfoRepresentation> executions = executionFlowRepository
                .getExecutionsByAuthFlow(realmImport.getRealm(), flowAliasForExecutionLookup);

        String executionConfigId = executions.stream()
                .filter(e -> Objects.equals(e.getId(), executionIdForCreation))
                .map(AuthenticationExecutionInfoRepresentation::getAuthenticationConfig)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);

        if (executionConfigId != null) {
            authenticatorConfigIdsByAlias.put(authenticatorConfigName, executionConfigId);
            return executionConfigId;
        }

        // If still not found, we need to create it.
        AuthenticatorConfigRepresentation definition = Optional
                .ofNullable(realmImport.getAuthenticatorConfig())
                .orElse(List.of())
                .stream()
                .filter(x -> Objects.equals(x.getAlias(), authenticatorConfigName))
                .findAny()
                .orElseThrow(() -> new ImportProcessingException(
                        String.format(
                                "Authenticator config '%s' definition not found",
                                authenticatorConfigName)));

        AuthenticatorConfigRepresentation configToCreate = new AuthenticatorConfigRepresentation();
        configToCreate.setAlias(definition.getAlias());
        configToCreate.setConfig(definition.getConfig());

        logger.debug(
                "Creating authenticator config '{}' by attaching it to execution '{}' in realm '{}'",
                authenticatorConfigName,
                executionIdForCreation,
                realmImport.getRealm());

        // This creates the config (realm-level) and attaches it to the execution.
        try {
            authenticatorConfigRepository.create(realmImport.getRealm(), executionIdForCreation,
                    configToCreate);
        } catch (WebApplicationException error) {
            // Keycloak 26.1+ may reject reusing an alias with a 409 Conflict.
            // In that case, we try to locate the already created config id one last time.
            logger.debug(
                    "Could not create authenticator config '{}' for execution '{}' (will try to reuse existing): {}",
                    authenticatorConfigName,
                    executionIdForCreation,
                    ResponseUtil.getErrorMessage(error));
        }

        // Final attempt to resolve the config id.
        List<AuthenticatorConfigRepresentation> created = authenticatorConfigRepository
                .getConfigsByAlias(realmImport.getRealm(), authenticatorConfigName);

        if (!created.isEmpty()) {
            String id = created.get(0).getId();
            authenticatorConfigIdsByAlias.put(authenticatorConfigName, id);
            return id;
        }

        // Fall back to reading from execution one last time
        executions = executionFlowRepository.getExecutionsByAuthFlow(realmImport.getRealm(),
                flowAliasForExecutionLookup);
        executionConfigId = executions.stream()
                .filter(e -> Objects.equals(e.getId(), executionIdForCreation))
                .map(AuthenticationExecutionInfoRepresentation::getAuthenticationConfig)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);

        if (executionConfigId != null) {
            authenticatorConfigIdsByAlias.put(authenticatorConfigName, executionConfigId);
            return executionConfigId;
        }

        throw new ImportProcessingException(String.format(
                "Authenticator config '%s' was expected but cannot be found or created in realm '%s'",
                authenticatorConfigName,
                realmImport.getRealm()));
    }

    private void debugLogExecutionFlowCreation(
            RealmImport realmImport,
            String authenticationFlowAlias,
            AuthenticationExecutionExportRepresentation executionToImport) {
        if (logger.isDebugEnabled()) {
            String execution = Optional.ofNullable(executionToImport.getFlowAlias())
                    .orElse(executionToImport.getAuthenticator());
            logger.debug("Configuring execution-flow '{}' for authentication-flow '{}' in realm '{}'",
                    execution, authenticationFlowAlias, realmImport.getRealm());
        }
    }
}
