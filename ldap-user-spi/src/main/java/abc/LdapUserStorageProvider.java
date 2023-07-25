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

import java.util.Map;
import java.util.stream.Stream;

import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.LegacyUserCredentialManager;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;

import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.util.Base64;
import com.unboundid.util.ssl.cert.X509Certificate;

public class LdapUserStorageProvider implements
        UserStorageProvider,
        UserLookupProvider,
        UserQueryProvider,
        CredentialInputValidator,
        CredentialInputUpdater {

    private static final Logger logger = Logger.getLogger(LdapUserStorageProvider.class);
    protected static final String CERTIFICATE_ATTRIBUTE_NAME = "usercertificate";

    protected KeycloakSession session;
    protected ComponentModel model;
    protected LDAPConnectionPool ldapConnectionPool;
    protected CacheManager cacheManager;
    protected Cache<String, UserModel> userCache;

    public LdapUserStorageProvider(KeycloakSession session, ComponentModel model,
            LDAPConnectionPool ldapConnectionPool) {
        this.session = session;
        this.model = model;
        this.ldapConnectionPool = ldapConnectionPool;
        cacheManager = CacheManagerBuilder.newCacheManagerBuilder().build(true);
        userCache = cacheManager.createCache("userCache", CacheConfigurationBuilder
                .newCacheConfigurationBuilder(String.class, UserModel.class, ResourcePoolsBuilder.heap(100)).build());
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel adapter = userCache.get(username);
        if (adapter == null) {
            adapter = createAdapter(realm, username);
            userCache.put(username, adapter);
        }
        return adapter;
    }

    protected UserModel createAdapter(RealmModel realm, String username) {
        return new AbstractUserAdapter(session, realm, model) {
            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public SubjectCredentialManager credentialManager() {
                return new LegacyUserCredentialManager(session, realm, this);
            }
        };
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(realm, username);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return null;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(CredentialModel.CLIENT_CERT);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        return false;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        throw new ReadOnlyException("LDAP user is read only");
    }

    @Override
    public void close() {
        cacheManager.close();
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult,
            Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult,
            Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult,
            Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        if (!attrName.equals(CERTIFICATE_ATTRIBUTE_NAME)) {
            return Stream.empty();
        }
        try {
            var cert = new X509Certificate(Base64.decode(attrValue));
            return Stream.of(createAdapter(realm, cert.getSubjectDN().toNormalizedString()));
        } catch (Exception e) {
            logger.error("Failure searching for user by certificate", e);
            return Stream.empty();
        }
    }

}