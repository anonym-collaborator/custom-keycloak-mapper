package com.example.keycloak;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.*;
import java.util.stream.Collectors;

public class CustomRealmRoleOnlyMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    public static final String PROVIDER_ID = "custom-realm-role-only-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomRealmRoleOnlyMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return "Role Mappers";
    }

    @Override
    public String getDisplayType() {
        return "Single Custom Realm Role Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds the user's only custom realm-level role (excluding default/composite) to the token if exactly one exists.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession session) {

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

    private boolean includesRole(RoleModel role, RoleModel target) {
        if (role.equals(target)) return true;
        return role.getCompositesStream().anyMatch(r -> includesRole(r, target));
    }

    public static ProtocolMapperModel create(String name, String claimName, boolean access, boolean id) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, claimName);
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, String.valueOf(access));
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, String.valueOf(id));
        mapper.setConfig(config);
        return mapper;
    }
}
