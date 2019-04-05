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
package org.keycloak.social.twitch;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:Emerson.Wu@acer.com">Wu Chin Long</a>
 */
public class TwitchIdentityProviderFactory extends AbstractIdentityProviderFactory<TwitchIdentityProvider> implements SocialIdentityProviderFactory<TwitchIdentityProvider> {

    public static final String PROVIDER_ID = "twitch";

    @Override
    public String getName() {
        return "Twitch";
    }

    @Override
    public TwitchIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new TwitchIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}