FROM quay.io/keycloak/keycloak:26.4.1

COPY ./target/custom-keycloak-mapper-1.0.0.jar /opt/keycloak/providers/

ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]
