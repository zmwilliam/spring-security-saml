
How to run a simple sample of an Identity Provider (IDP) and Service Provider (SP)

**Step 1 - Get the Source** 

    git clone https://github.com/spring-projects/spring-security-saml.git
    cd spring-security-saml

**Step 2 - Start the Service Provider**

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-starter:bootRun

Please use

    url: http://localhost:8080/sample-sp
    username: user
    password: password
    
**Try it out**

***Against a running SimpleSamlPHP Server***

* Spring Security SAML [as a Service Provider](http://localhost:8080/sample-sp)
* Spring Security SAML [as an initiating Service Provider](http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php?spentityid=http://localhost:8080/sample-sp)

Please use

    username: user
    password: password

**Sample Descriptions**

***Starter Sample***

The [Spring Boot Starter sample](service-provider/starter) showcases the use of 
a Spring Boot application with the use of a minimal 
[default registration](service-provider/starter/src/main/java/org/springframework/security/saml2/samples/SecurityConfig.java)
to configure the SAML Service Provider. 

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-mvp-samples-service-provider-starter:bootRun

In order to have the sample run, we need to configure at least a private key/certificate
along with one remote Identity Provider (IDP). 
