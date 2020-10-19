
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