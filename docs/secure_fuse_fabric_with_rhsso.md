
# Secure a _Fuse Fabric_ environment with _Red Hat SSO 7.3_

## Assumptions and pre-requisites

- It is assumed _Red Hat SSO 7.3.8_ (upstream _keycloak_ version: _4.8.20.Final-redhat-00001_) is leveraged to secure the _Fuse Fabric_ environment 
- The _Red Hat SSO 7.3 Client Adapter for fuse_ maven artifacts available either via _Nexus_ or _Artifactory_ or other accessible maven repository integrated with _Fuse 6.3 Fabric_ environment. For instance, the _Red Hat SSO **7.3.8** Client Adapter for fuse_ can be downloaded via this [link](https://access.redhat.com/jbossnetwork/restricted/softwareDetail.html?softwareId=81921&product=core.service.rhsso&version=7.3&downloadType=securityPatches).
- Reference documentation: [_JBoss Fuse 6 Adapter_ for _Red Hat SSO 7.3_](https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.3/html/securing_applications_and_services_guide/openid_connect_3#fuse_adapter)
- :warning: **NOTE - when _SSH_ and/or _JMX_ interfaces (_administration_) ** are secured with _Red Hat SSO_**:
- If _OTP_ is set on users, make sure it is disabled on the `Direct Grant` Authentication Flow to allow access on _SSH_ and _JMX_ endpoints secured with _Red Hat SSO_
- The following `realm roles` must be added to the _Red Hat SSO_ realm securing the _Fuse Fabric_ environment (e.g. `fuse-fabric-demo`): 
  ```
  admin
  manager
  viewer
  Monitor
  Operator
  Maintainer
  Deployer
  Auditor
  Administrator
  SuperUser
  ```

## Used variables

- `<console_vip>`: VIP fqdn for the _fabric ensemble hawtio_ consoles
- `<console_vip_port>`: VIP listening port for the _fabric ensemble hawtio_ consoles
- `<ssh-jmx-admin-client_secret>`: _Red Hat SSO_ `ssh-jmx-admin-client` secret. This client secures the _Fuse_ administration services (_SSH_ and _JMX_ interfaces). For example, `ab91126a-e4eb-4156-9f02-aa8a1fd710b9`
- `<path_to_keystores>`: absolute path to the keystores folder. For instance, For example, `/Users/jnyilimb/workdata/opt/fuse-karaf/jboss-fuse-6_3/fabric/security`

## Create Red Hat SSO _clients_ for the secured _Fuse Fabric_ environment interfaces

### `hawtio-client` to secure the _Fabric Hawtio console_

Create the `hawtio-client` client in a _Red Hat SSO 7.3_ realm (e.g. `fuse-fabric-demo`) with the following attributes:

- `Client ID`: `hawtio-client`
- `Access type` must be `public`
- `Redirect URI` must point to _Fuse Fabric_ environment _Hawtio_. For instance: `https://localhost:8443/hawtio/*` or `https://<console_vip>:<console_vip_port>/hawtio/*`
  - You must also have a corresponding _Web Origin_ configured. In this case, `https://localhost:8443` or `https://<vip_host>:<vip_port>`
- `Full Scope Allowed` selected to `OFF` and restrict realm roles to the following. Note that the user needs to have the proper role to successfully authenticate to _Hawtio_:
  ```
  admin
  manager
  viewer
  Monitor
  Operator
  Maintainer
  Deployer
  Auditor
  Administrator
  SuperUser
  ```

### `ssh-jmx-admin-client` to secure the _Fuse_ administration services

Create the `ssh-jmx-admin-client` client in a _Red Hat SSO 7.3_ realm (e.g. `fuse-fabric-demo`) with the following attributes:

- `Client ID`: `ssh-jmx-admin-client`
- `Access type` must be `confidential`
- `Direct Access Grants Enabled` selected to `ON`
- `Redirect URI` field is mandatory but not used in this case. You can provide a dummy URL. For instance: `https://dummy/*`
- `Full Scope Allowed` selected to `OFF` and restrict realm roles to the following. Note that the user needs to have `admin` role to perform all operations or another role to perform a subset of operations (for example, the `viewer` role that restricts the user to run only read-only _Karaf_ commands):
  ```
  admin
  manager
  viewer
  Monitor
  Operator
  Maintainer
  Deployer
  Auditor
  Administrator
  SuperUser
  ```

## Create customized _fabric profiles_ to secure the _Fuse Fabric_ environment

### `rh-sso-hawtio` _fabric profile_ to secure the _Fabric Hawtio console_

1. Create the `rh-sso-hawtio` _fabric profile_ with the following instructions:
    ```zsh
    fabric:profile-create --parent default rh-sso-hawtio 
    fabric:profile-edit --system hawtio.realm=keycloak rh-sso-hawtio
    fabric:profile-edit --system hawtio.rolePrincipalClasses=org.keycloak.adapters.jaas.RolePrincipal,org.apache.karaf.jaas.boot.principal.RolePrincipal rh-sso-hawtio
    fabric:profile-edit --system hawtio.keycloakEnabled=true rh-sso-hawtio 
    fabric:profile-edit --system hawtio.keycloakClientConfig=profile:keycloak-hawtio-client.json rh-sso-hawtio
    fabric:profile-edit --pid org.keycloak/jaasBearerKeycloakConfigFile=profile:keycloak-hawtio.json rh-sso-hawtio
    fabric:profile-edit --repository mvn:org.keycloak/keycloak-osgi-features/4.8.20.Final-redhat-00001/xml/features rh-sso-hawtio
    fabric:profile-edit --feature keycloak rh-sso-hawtio
    ```
 
2. Add the `keycloak-hawtio-client.json` and `keycloak-hawtio.json` files as _resources_ to the `rh-sso-hawtio` _fabric profile_  (either via the _Fabric Hawtio console_ or via the `git` command usage). The contents of these files should be similar to the following (adapt the property values according to your environment):
    -	`keycloak-hawtio-client.json` - this file is used by _Red Hat SSO 7.3 Client Adapter for fuse_ on the client (_Hawtio JavaScript application_) side.
        ```json
        {
          "realm": "fuse-fabric-demo",
          "auth-server-url": "https://sso.apps.cluster-eb10.sandbox1401.opentlc.com/auth",
          "ssl-required": "all",
          "resource": "hawtio-client",
          "public-client": true,
          "confidential-port": 0,
          "truststore" : "<path_to_keystores>/fuse_ts.jks",
          "truststore-password" : "P@ssw0rd"
        }
        ```
    -	`keycloak-hawtio.json` - this file is used by the _Red Hat SSO 7.3 Client Adapter for fuse_ on the server (JAAS Login module) side.
        ```json
        {
          "realm" : "fuse-fabric-demo",
          "resource" : "jaas",
          "bearer-only" : true,
          "auth-server-url" : "https://sso.apps.cluster-eb10.sandbox1401.opentlc.com/auth",
          "ssl-required" : "all",
          "use-resource-role-mappings": false,
          "principal-attribute": "preferred_username",
          "allow-any-hostname" : false,
          "truststore" : "<path_to_keystores>/fuse_ts.jks",
          "truststore-password" : "P@ssw0rd"
        }
        ```
3. Deploy the custom `rh-sso-hawtio` _fabric profile_ to the _fabric ensemble containers_ or _fabric root managed containers_
    ```zsh
    fabric:container-add-profile fabric-server rh-sso-hawtio
    ```

### `rh-sso-administration` _profile_ to secure the _Fuse_ administration services (_SSH_ and _JMX_ interfaces)

1. Create the `rh-sso-administration` _fabric profile_ with the following instructions:
    ```zsh
    fabric:profile-create --parent default rh-sso-administration
    fabric:profile-edit --pid io.fabric8.jolokia/realm=keycloak rh-sso-administration 
    fabric:profile-edit --pid org.keycloak/jaasDirectAccessKeycloakConfigFile=profile:keycloak-direct-access.json rh-sso-administration
    fabric:profile-edit --repository mvn:org.keycloak/keycloak-osgi-features/4.8.20.Final-redhat-00001/xml/features rh-sso-administration
    fabric:profile-edit --feature keycloak-jaas rh-sso-administration
    ```

2. Add the `keycloak-direct-access.json` file as _resource_ to the `rh-sso-administration` _fabric profile_  (either via the _Fabric Hawtio console_ or via the `git` command usage). The content of this file should be similar to the following (adapt the property values according to your environment):
    -	`keycloak-direct-access.json` - this file specifies the client application configuration, which is used by _JAAS DirectAccessGrantsLoginModule_ from the _keycloak_ _JAAS_ realm for _SSH_ and _JMX_ authentication
      ```json
      {
        "realm": "fuse-fabric-demo",
        "auth-server-url": "https://sso.apps.cluster-eb10.sandbox1401.opentlc.com/auth",
        "ssl-required": "all",
        "resource": "ssh-jmx-admin-client",
        "credentials": {
          "secret": "<ssh-jmx-admin-client_secret>"
        },
        "confidential-port": 0,
        "truststore" : "<path_to_keystores>/fuse_ts.jks",
        "truststore-password" : "P@ssw0rd"
      }
      ```

3. Deploy the custom `rh-sso-administration` _fabric profile_ to all the _fuse fabric_environment containers (_fabric servers_ or _fabric containers_/_managed containers_). 
    1. Start with the _managed containers_. For each _managed container_:
        1. Add the `rh-sso-administration` _fabric profile_
            ```zsh
            fabric:container-add-profile <fabric_container_name> rh-sso-administration
            ```

        2. Run the following command lines in order to make the _SSH_ and _JMX_ realms use _keycloak_ as identity provider. 
            ```zsh
            fabric:container-connect <fabric_container_name> 'config:propset -p org.apache.karaf.management jmxRealm keycloak'
            fabric:container-connect <fabric_container_name> 'config:propset -p org.apache.karaf.shell sshRealm keycloak'
            ```

        3. The container will take into account the new _PID_ keys values automatically.

    2. Repeat the same steps above for each _fabric server_.