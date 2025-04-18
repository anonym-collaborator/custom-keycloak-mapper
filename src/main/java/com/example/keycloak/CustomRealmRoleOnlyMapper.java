package com.example.keycloak;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.protocol.oidc.*;
import org.keycloak.provider.*;
import org.keycloak.representations.IDToken;

import java.util.*;
import java.util.stream.Collectors;

public class CustomRealmRoleOnlyMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    public static final String PROVIDER_ID = "auto-custom-realm-role-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomRealmRoleOnlyMapper.class);
    }

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
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = userSession.getUser();
        RoleModel defaultRole = realm.getRole("default-roles-" + realm.getName());

        Set<RoleModel> realmRoles = user.getRoleMappings().stream()
                .filter(r -> r.getContainer() instanceof RealmModel)
                .filter(r -> !includesRole(r, defaultRole))
                .collect(Collectors.toSet());

        if (realmRoles.size() == 1) {
            String roleName = realmRoles.iterator().next().getName();
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, roleName);
        }
    }

    private boolean includesRole(RoleModel role, RoleModel roleToExclude) {
        if (role.equals(roleToExclude)) return true;
        if (role.isComposite()) {
            return role.getComposites().stream().anyMatch(r -> includesRole(r, roleToExclude));
        }
        return false;
    }
}
