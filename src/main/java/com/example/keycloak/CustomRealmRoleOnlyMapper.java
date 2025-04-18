
package com.example.keycloak;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.protocol.oidc.*;
import org.keycloak.representations.AccessToken;

import java.util.*;

public class CustomRealmRoleOnlyMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "auto-custom-realm-role-mapper";

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Auto Custom Realm Role Mapper";
    }

    @Override
    public String getHelpText() {
        return "Includes only custom realm role(s) in access token, excluding default-roles-<realm>";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
                                     KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        RealmModel realm = session.getContext().getRealm();
        UserModel user = userSession.getUser();

        Set<RoleModel> realmRoles = user.getRealmRoleMappings();

        for (RoleModel role : realmRoles) {
            String roleName = role.getName();

            if (!roleName.startsWith("default-roles-")) {
                token.getRealmAccess().addRole(roleName);
            }
        }
    }
}
