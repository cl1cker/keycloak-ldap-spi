/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package abc;

import java.time.Duration;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.SingleServerSet;

public class LdapUserStorageProviderFactory implements UserStorageProviderFactory<LdapUserStorageProvider> {
    public static final String PROVIDER_NAME = "ldap-user-storage";
    public static final String LDAP_HOST = "ldapHost";
    public static final String LDAP_PORT = "ldapPort";

    protected LDAPConnectionPool ldapConnectionPool;

    protected static final List<ProviderConfigProperty> configMetadata;

    static {
        configMetadata = ProviderConfigurationBuilder.create()
                .property()
                .name(LDAP_HOST)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("LDAP Server Hostname")
                .add()
                .property()
                .name(LDAP_PORT)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("LDAP Server Port")
                .add()
                .build();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
            throws ComponentValidationException {
        String ldapHost = config.get(LDAP_HOST);
        int ldapPort = config.get(LDAP_PORT, -1);
        if (ldapHost == null || ldapPort < 0 || ldapPort > 65535) {
            throw new ComponentValidationException("Valid LDAP URL and Port are required");
        }

        try {
            // TODO: make keystores, pool sizes, and timeouts config options?
            // var keyManager = new KeyStoreKeyManager("", "".toCharArray());
            // var trustManager = new TrustStoreTrustManager("");
            // var sslUtil = new SSLUtil(keyManager, trustManager);
            // var sslSocketFactory = sslUtil.createSSLSocketFactory();
            // Use system SSLContext
            var sslSocketFactory = SSLContext.getDefault().getSocketFactory();
            var serverSet = new SingleServerSet(ldapHost, ldapPort, sslSocketFactory);
            ldapConnectionPool = new LDAPConnectionPool(serverSet, new EXTERNALBindRequest(), 1, 3);
            ldapConnectionPool.setCreateIfNecessary(true);
            ldapConnectionPool.setMaxConnectionAgeMillis(Duration.ofMinutes(10).toMillis());
            ldapConnectionPool.setMaxWaitTimeMillis(Duration.ofSeconds(10).toMillis());
            ldapConnectionPool.setRetryFailedOperationsDueToInvalidConnections(true);
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize LDAP Connection Pool", e);
        }
    }

    @Override
    public LdapUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new LdapUserStorageProvider(session, model, ldapConnectionPool);
    }

}