# Proof of Concept - MVP - Nothing but Log In

## Functionality Supported

IDP Initiated Log In

### Authentication

The sample is able to receive an assertion, unsigned, signed or encrypted, and authenticate 
the user in the local application based on mutual trust with the identity provider. (IDP) 

## Showcase

1. Start up Spring Security Boot Sample
```
    ./gradlew :spring-security-saml2-samples-service-provider-starter:bootRun
```

1. IDP Initiated Login
```
    URL : http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php?spentityid=http://localhost:8080/sample-sp
    User: user
    Password: password
```

 
### Test Support

