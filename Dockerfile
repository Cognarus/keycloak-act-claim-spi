FROM quay.io/keycloak/keycloak:26.7.0

COPY target/keycloak-act-claim-spi-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build
