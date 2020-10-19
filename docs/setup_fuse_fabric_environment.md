# Generate a self-signed key pair

1. Generate a self-signed keystore containing a key pair to identity to _Fuse Fabric_ environment
    ```zsh
    keytool -genkeypair -keyalg RSA -keysize 2048 -validity 3650 \
    -dname "CN=fuse-fabric,OU=Red Hat Consulting,O=Red Hat France,L=Paris,ST=Ile De France,C=FR" \
    -alias fuse-fabric \
    -keypass P@ssw0rd -storepass P@ssw0rd \
    -v -ext "san=DNS:localhost" \
    -keystore fuse-fabric-ssl.jks
    ```

2. Export the _Fuse Fabric_ public auto-signed certificate (`fuse-fabric.cert`)
  ```zsh
  keytool -export -alias fuse-fabric \
  -keystore fuse-fabric-ssl.jks \
  -storepass P@ssw0rd -v \
  -file fuse-fabric.cert
  ```

3. Create the _Fuse Fabric_ truststore (`fuse_ts.jks`) containing the _Fuse Fabric_ public certificate (`fuse-fabric.cert`)
```zsh
keytool -import -alias fuse-fabric \
-keystore fuse_ts.jks \
-storepass P@ssw0rd -keypass P@ssw0rd \
-v -noprompt \
-file fuse-fabric.cert 
```

# Creating a _JBoss Fuse 6.3 Fabric_ on a local machine

## Used variables:
- `<crypted_password>`: encrypted password using `fabric:encrypt-message` command. For example, `MkLYSntvjEMD2nSyyBkePJ9ajg+WhaBl` obtained through the following instruction:
  ```
  JBossFuse:karaf@fabric-server> fabric:crypt-algorithm-get
  PBEWithMD5AndDES
  JBossFuse:karaf@fabric-server> fabric:encrypt-message P@ssw0rd
  Encrypting message P@ssw0rd
  Using algorithm PBEWithMD5AndDES and password P@ssw0rd
  Result: MkLYSntvjEMD2nSyyBkePJ9ajg+WhaBl
  ``` 

- `<fuse_install_dir>`: installation home directory for _Red Hat Jboss Fuse 6.3_. For example, `/Users/jnyilimb/workdata/opt/fuse-karaf/jboss-fuse-6_3/fabric/jboss-fuse-6.3.0.redhat-356`

- `<path_to_keystores>`: absolute path to the keystores folder. For instance, For example, `/Users/jnyilimb/workdata/opt/fuse-karaf/jboss-fuse-6_3/fabric/security`.

## Create a _Fabric Server_

1. Name the current _Fuse_ root server instance `fabric-server` by editing the `<install_dir>/etc/system.properties` `karaf.name` property.
    ```properties
    #
    # Name of this Karaf instance.
    #
    karaf.name = fabric-server
    ```

2. Declare the _Fuse Fabric_ truststore (`fuse_ts.jks`), containing the _Fuse Fabric_ public certificate (`fuse-fabric.cert`), on the _Fuse_ root server:
  ```zsh
  # export EXTRA_JAVA_OPTS # Additional JVM options
  export EXTRA_JAVA_OPTS='-Djavax.net.ssl.trustStorePassword=P@ssw0rd -Djavax.net.ssl.trustStore=<path_to_keystores>/fuse_ts.jks'
  ```

3. Start the _fuse_ server in foreground
  ```zsh
  <fuse_install_dir>/bin/fuse
  ```

4.	Create a secure (`TLS`-enabled) _Fuse Fabric_ environment with only one _fabric server_ (_fabric ensemble_ of only 1 server):
    ```zsh
    fabric:create --clean --new-user admin --new-user-password admin123 \
    --new-user-role admin,manager,viewer,Monitor,Operator,Maintainer,Deployer,Auditor,Administrator,SuperUser \
    --zookeeper-password P@ssw0rd --resolver manualip --global-resolver manualip \
    --manual-ip localhost --profile fabric \
    --verbose --wait-for-provisioning
    ```

## Create customized profiles

### Customized `ssl` profile to enable `SSL/TLS` on the `jetty` server 

Run the following command lines:

```zsh
profile-create --parent default ssl
profile-edit --pid org.ops4j.pax.web/org.osgi.service.http.enabled=false ssl
profile-edit --pid org.ops4j.pax.web/org.osgi.service.http.secure.enabled=true ssl
profile-edit --pid org.ops4j.pax.web/org.osgi.service.http.port.secure=\${port:8443,8543} ssl
profile-edit --pid org.ops4j.pax.web/org.ops4j.pax.web.ssl.keystore=<path_to_keystores>/fuse-fabric-ssl.jks ssl
profile-edit --pid org.ops4j.pax.web/org.ops4j.pax.web.ssl.keystore.type=jks ssl
profile-edit --pid org.ops4j.pax.web/org.ops4j.pax.web.ssl.password=\${crypt:<crypted_password>} ssl
profile-edit --pid org.ops4j.pax.web/org.ops4j.pax.web.ssl.keypassword=\${crypt:<crypted_password>} ssl
```

### Customized `gateway-http` profile

Run the following command lines to enforce the indicated customisations:

1. Create the customized `ws-http-gateway` profile
  ```zsh
  fabric:profile-create --parent gateway-http ws-http-gateway
  ```
  ```zsh
  fabric:profile-edit -p io.fabric8.gateway.http.mapping-apis/zooKeeperPath=/fabric/registry/clusters/apis ws-http-gateway
  ```

2. Deactivate the automatic addition of trailing forward slashes when the URL does not have one: `addMissingTrailingSlashes=false`
  ```zsh
  fabric:profile-edit -p io.fabric8.gateway.http/addMissingTrailingSlashes=false ws-http-gateway
  ```
3. Enforce explicit URI versioning by customising the URI template: `/version/{version}{contextPath}/`
  ```zsh
  fabric:profile-edit -p io.fabric8.gateway.http.mapping-apis/uriTemplate=/version/{version}{contextPath}/ ws-http-gateway
  ```

### Customized `ws-https-gateway` profile to secure the web services

This profile must be deployed in the same container as the customised `ws-http-gateway` (see above) for the workaround to work. Below are the reasons of this workaround:
- The `gateway-http` profile does not support `SSL`
- The `gateway-mq` supports `SSL` termination and `HTTP`. Thus, the `HTTP` and `SSL` protocols are the only activated protocols so it serves only for detecting `HTTP` after `SSL` termination. 
- The workaround works as follows:
  ```zsh
  HTTPS -gateway-mq-> HTTP -gateway-http-> discovered HTTP services
  ```

Run the following command lines:
```zsh 
fabric:profile-create --parent gateway-mq ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/mqttEnabled=false ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/openWireEnabled=false ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/stompEnabled=false ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/amqpEnabled=false ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/httpEnabled=true ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/port=9095 ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/sslEnabled=true ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/keyStoreURL=file://<path_to_keystores>/fuse-fabric-ssl.jks ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/keyPassword=\${crypt:<crypted_password>} ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/keyStorePassword=\${crypt:<crypted_password>} ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/trustStoreURL=file://<path_to_keystores>/fuse_ts.jks ws-https-gateway
fabric:profile-edit -p io.fabric8.gateway.detecting/trustStorePassword=\${crypt:<crypted_password>} ws-https-gateway
```

## Secure the `jetty` server of the _fabric server_

1. Deploy the custom `ssl` profile on the _fabric-server_ container
  ```zsh
  fabric:container-add-profile fabric-server ssl
  ```

2. Exit the _fabric-server_ shell
  ```zsh
  exit
  ```

3. Start the _fabric-server_ service
  ```zsh
  <fuse_install_dir>/bin/start
  ```

4. Verify the _fabric-server_ is running
  ```zsh
  $ <fuse_install_dir>/bin/status
  Running ...
  ```

## Create _Fabric containers_ (managed containers)

1.	Create the `ws-gateway-node` managed container for Web Services gateways
    ```zsh
    fabric:container-create-child \
    --jvm-opts='-Djavax.net.ssl.trustStore=<path_to_keystores>/fuse_ts.jks -Djavax.net.ssl.trustStorePassword=P@ssw0rd' \
    --profile ssl \
    --profile ws-http-gateway \
    --profile ws-https-gateway \
    fabric-server ws-gateway-node
    ```

2.	Create the `msg-brokers-node` managed container for _JBoss AMQ 6.3_ brokers
    ```zsh
    fabric:container-create-child \
    --jvm-opts='-Djavax.net.ssl.trustStore=<path_to_keystores>/fuse_ts.jks -Djavax.net.ssl.trustStorePassword=P@ssw0rd' \
    --profile ssl \
    --profile gateway-mq \
    fabric-server msg-brokers-node
    ```

3.	Create the `fuse-apps-node` managed container for _Fuse 6.3_ applications
    ```zsh
    fabric:container-create-child \
    --jvm-opts='-Djavax.net.ssl.trustStore=<path_to_keystores>/fuse_ts.jks -Djavax.net.ssl.trustStorePassword=P@ssw0rd' \
    --profile ssl \
    fabric-server fuse-apps-node
    ```

ATTENTION - NOT TO FORGET:

The truststore for each root container should be set in the <FUSE_HOME>/bin/setenv script under the additional _JVM_ options variable (`EXTRA_JAVA_OPTS`).

# Secure a Fabric Hawtio console with Red Hat SSO 7.2

## Pre-requisites
 
Make sure the following json files are positioned in the ${karaf.etc} directory:


 NOTE: Thanks to https://access.redhat.com/support/cases/#/case/01929341, it will be             possible to reference the json resources using the fabric profile handler


-	keycloak-direct-access.json (please, adapt below content accordingly)
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
-	keycloak-hawtio-client.json (please, adapt below content accordingly)
{
  "realm": "demo",
  "auth-server-url": "https://localhost:8443/auth",
  "ssl-required": "all",
  "resource": "hawtio-client",
  "public-client": true,
  "truststore" : "/Users/jnyilimb/workspace/security/fuse/truststore.jks",
  "truststore-password" : "P@ssw0rd"
}
-	keycloak-hawtio.json (please, adapt below content accordingly)
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
Create the rh-sso-hawtio profile to secure the Fuse Management Console Hawtio
 $ profile-create --parent default rh-sso-hawtio 
 $ profile-edit --system hawtio.realm=keycloak rh-sso-hawtio
 $ profile-edit --system hawtio.rolePrincipalClasses=org.keycloak.adapters.
   jaas.RolePrincipal,org.apache.karaf.jaas.boot.principal.RolePrincipal
   rh-sso-hawtio
 $ profile-edit --system hawtio.keycloakEnabled=true rh-sso-hawtio 
 $ profile-edit --system hawtio.keycloakClientConfig=profile:keycloak-
   hawtio-client.json rh-sso-hawtio
 $ profile-edit --pid org.keycloak/jaasBearerKeycloakConfigFile=
   profile:keycloak-hawtio.json rh-sso-hawtio
 $ profile-edit --repository mvn:org.keycloak/keycloak-osgi-features/
   3.4.3.Final-redhat-2/xml/features rh-sso-hawtio
 $ profile-edit --feature keycloak rh-sso-hawtio
 
Add the keycloak-hawtio-client.json and keycloak-hawtio.json files as resources to the rh-sso-hawtio profile  (through Hawtio or through the git command)

Create the rh-sso-administration profile to secure the administration services (SSH and JMX)
 $ profile-create --parent default rh-sso-administration
 $ profile-edit --pid io.fabric8.jolokia/realm=keycloak  
   rh-sso-administration 
 $ profile-edit --pid org.keycloak/jaasDirectAccessKeycloakConfigFile=
   profile:keycloak-direct-access.json rh-sso-administration
 $ profile-edit --repository mvn:org.keycloak/keycloak-osgi-features/
   3.4.3.Final-redhat-2/xml/features rh-sso-administration
 $ profile-edit --feature keycloak-jaas rh-sso-administration
Add the keycloak-direct-access.json files as resources to the rh-sso-administration profile (through Hawtio or through the git command)

For Hawtio, add the rh-sso-hawtio profile to ensemble containers or fabric root managed containers
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

ATTENTION:

If OTP is set on users, make sure it is disabled on the ‘Direct Grant’ Authentication Flow to allow access on SSH and JMX endpoints secured by RH-SSO

ATTENTION when SSH is secured via RH-SSO:

Authenticated user with adequate privileges cannot start containers. Hawtio seems to use the Fabric admin user by default:

JBoss Fuse 6.3.0.R4 defect:

After update JBoss Fuse 6.3 to 6.3 R4, we are getting "org.xml.sax.SAXNotRecognizedException: Property 'http://javax.xml.XMLConstants/property/accessExternalDTD' is not recognized” [1]
This is fixed in JBoss Fuse 6.3.0.R5
[1] https://access.redhat.com/solutions/3184641


# Example of Fuse Fabric8 topology with Insight

![FuseFabric8TopologyWithInsight_example.png](../images/FuseFabric8TopologyWithInsight_example.png)