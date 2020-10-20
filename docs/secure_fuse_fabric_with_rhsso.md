
# Secure a _Fuse Fabric_ environment with _Red Hat SSO 7.3_

## Assumptions and pre-requisites

- It is assumed _Red Hat SSO 7.3.8_ (upstream _keycloak_ version: _4.8.20.Final-redhat-00001_) is leveraged to secure the _Fuse Fabric_ environment 
- The _Red Hat SSO 7.3 Client Adapter for fuse_ maven artifacts available either via _Nexus_ or _Artifactory_ or other accessible maven repository integrated with _Fuse 6.3 Fabric_ environment. For instance, the _Red Hat SSO **7.3.8** Client Adapter for fuse_ can be downloaded via this [link](https://access.redhat.com/jbossnetwork/restricted/softwareDetail.html?softwareId=81921&product=core.service.rhsso&version=7.3&downloadType=securityPatches)
- Reference documentation: [_JBoss Fuse 6 Adapter_ for _Red Hat SSO 7.3_](https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.3/html/securing_applications_and_services_guide/openid_connect_3#fuse_adapter)
- :warning: **NOTE - when _SSH_ and/or _JMX_ interfaces (_administration_) ** are secured with _Red Hat SSO_**:
- If _OTP_ is set on users, make sure it is disabled on the ‘Direct Grant’ Authentication Flow to allow access on _SSH_ and _JMX_ endpoints secured with _Red Hat SSO_
- Authenticated user with adequate roles cannot start containers. Hawtio seems to use the Fabric _admin_ user by default.

## Create Red Hat SSO _clients_ for the secured _Fuse Fabric_ environment interfaces

### `hawtio-client` to secure the _Fabric Hawtio console_

Create the `hawtio-client` client in a _Red Hat SSO 7.3_ realm (e.g. `fuse-fabric-demo`) with the following attributes:
- `Access type` must be `public`
- `Redirect URI` must point to _Fuse Fabric_ environment _Hawtio_. For instance: `https://localhost:8443/hawtio/*` or `https://<console_vip>:<console_vip_port>/hawtio/*`
  - You must also have a corresponding _Web Origin_ configured. In this case, `https://localhost:8443` or `https://<vip_host>:<vip_port>`
- The following `client roles` must be added to the `hawtio-client` (according to the _Fuse Fabric_ environment creation):
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

:construction: *TODO*

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
 
2. Add the `keycloak-hawtio-client.json` and `keycloak-hawtio.json` files as _resources_ to the `rh-sso-hawtio` _fabric profile_  (either via the _Fabric Hawtio console_ or via the `git` command usage).

    -	`keycloak-hawtio-client.json` (please, adapt below content according to your environment)
        ```json
        {
          "realm": "demo",
          "auth-server-url": "https://localhost:8443/auth",
          "ssl-required": "all",
          "resource": "hawtio-client",
          "public-client": true,
          "truststore" : "/Users/jnyilimb/workspace/security/fuse/truststore.jks",
          "truststore-password" : "P@ssw0rd"
        }
        ```
    -	`keycloak-hawtio.json` (please, adapt below content according to your environment)
        ```json
        {
          "realm" : "demo",
          "resource" : "jaas",
          "bearer-only" : true,
          "auth-server-url" : "https://localhost:8443/auth",
          "ssl-required" : "all",
          "use-resource-role-mappings": false,
          "principal-attribute": "preferred_username",
          "allow-any-hostname" : false,
          "truststore" : "/Users/jnyilimb/workspace/security/fuse/truststore.jks",
          "truststore-password" : "P@ssw0rd"
        }
        ```
3. Deploy the custom `rh-sso-hawtio` _fabric profile_ to the _fabric ensemble containers_ or _fabric root managed containers_
    ```zsh
    fabric:container-add-profile fabric-server ssl
    ```


### `rh-sso-administration` _profile_ to secure the _Fabric Hawtio console_
Create the rh-sso-administration profile to secure the administration services (SSH and JMX)
 $ fabric:profile-create --parent default rh-sso-administration
 $ fabric:profile-edit --pid io.fabric8.jolokia/realm=keycloak  
   rh-sso-administration 
 $ fabric:profile-edit --pid org.keycloak/jaasDirectAccessKeycloakConfigFile=
   profile:keycloak-direct-access.json rh-sso-administration
 $ fabric:profile-edit --repository mvn:org.keycloak/keycloak-osgi-features/
   3.4.3.Final-redhat-2/xml/features rh-sso-administration
 $ fabric:profile-edit --feature keycloak-jaas rh-sso-administration
Add the keycloak-direct-access.json files as resources to the rh-sso-administration profile (through Hawtio or through the git command)

-	`keycloak-direct-access.json` (please, adapt below content according to your environment)
    ```json
    {
      "realm": "demo",
      "auth-server-url": "https://localhost:8443/auth",
      "ssl-required": "all",
      "resource": "ssh-jmx-admin-client",
      "credentials": {
        "secret": "ab91126a-e4eb-4156-9f02-aa8a1fd710b9"
      },
      "truststore" : "/Users/jnyilimb/workspace/security/fuse/truststore.jks",
      "truststore-password" : "P@ssw0rd"
    }
    ```

For Administration Services, perform the following the steps on each container in a fabric
Add the rh-sso-administration profile
Connect to the container through fabric:container-connect command
Run the following commands in the Fuse CLI to change respectively the SSH and JMX realms to use keycloak. (Most of the time, the org.apache.karaf.management/sshRealm PID property is automatically set while deploying the rh-sso-administration profile)

 $ config:propset -p org.apache.karaf.shell sshRealm keycloak
 $ config:propset -p org.apache.karaf.management jmxRealm keycloak

The container will take into account the new PID key values automatically.

Workaround: put the *.json files in the ${karaf.etc} directory
 $ cat profile:keycloak-hawtio-client.json | tac -f “${karaf.etc}/keycloak-hawtio-client.json"
 $ cat profile:keycloak-hawtio-client.json | tac -f “${karaf.etc}/keycloak-hawtio-client.json"
 $ cat profile:keycloak-hawtio-client.json | tac -f “${karaf.etc}/keycloak-hawtio-client.json”