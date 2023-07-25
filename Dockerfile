FROM docker.io/maven:latest as spi-builder

WORKDIR /spi
COPY ldap-user-spi .
RUN mvn package && ls -l target

FROM quay.io/keycloak/keycloak:21.1.2 as keycloak-builder

ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_DB=dev-file

WORKDIR /opt/keycloak
COPY --chown=keycloak:keycloak --from=spi-builder /spi/target/*.jar /opt/keycloak/providers/
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:21.1.2
COPY --from=keycloak-builder /opt/keycloak/ /opt/keycloak/
ENV KC_HOSTNAME=localhost
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]