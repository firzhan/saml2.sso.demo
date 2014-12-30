 How to get a session cookie from a webapp which uses SAML SSO
===============================================================

I have written a sample web-app where password is updated by using SAML token.

I have modified the code provided in following article [1]. Original Code can be found from following location [2]. 


In this sample app, cookie is obtained by passing the SAML response to the admin service SAML2SSOAuthenticationService. Hence this cookie is used to invoke the changePasswordByUser method. 

I have written this sample to work with Tomcat. So I have packed some of jars in to lib folder. You can modify the pom by adding <scope>provided</scope> tag in to dependencies to suit your execution environment. 
prerequisite 
============ 

WSO2 IS server 5.0 - PORT 9443 ( PortOffset 0 ) 
TOMCAT 7 - PORT 8080 

Steps 
===== 
 -1 In order to test this sample you have to build the POM file using "mvn clean install". 
    The war file "saml2.sso.demo.war" can be found in target folder. 

 -2 Configure WSO2 IS 5.0 for SSO by using following link [3]. 
    Make sure to have following configuration values when configuring SP. 

    Issuer - "saml2.sso.demo" 
    Assertion Consumer URL - "http://localhost:8080/saml2.sso.demo/consumer" 

    Enable the Response signing and Assertion signing by checking the check boxes. 

 -3 Naviagte to repository/conf/security/authenticators.xml and update the "ServiceProviderID"'s value same as Issuer's value. 
    ( I have copied the XML here ) 

    <Authenticator name="SAML2SSOAuthenticator" disabled="true"> 
        <Priority>10</Priority> 
        <Config> 
            <Parameter name="LoginPage">/carbon/admin/login.jsp</Parameter> 
            <Parameter name="ServiceProviderID">saml2.sso.demo</Parameter> ( Place to be changed ) 
            <Parameter name="IdentityProviderSSOServiceURL">https://localhost:9443/samlsso&lt;/Parameter> 
            <Parameter name="NameIDPolicyFormat">urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</Parameter> 

            <!-- <Parameter name="IdPCertAlias">wso2carbon</Parameter> --> 
            <!-- <Parameter name="ResponseSignatureValidationEnabled">false</Parameter> --> 
            <!-- <Parameter name="LoginAttributeName"></Parameter> --> 
            <!-- <Parameter name="RoleClaimAttribute"></Parameter> --> 
            <!-- <Parameter name="AttributeValueSeparator">,</Parameter> --> 

            <!-- <Parameter name="JITUserProvisioning">true</Parameter> --> 
            <!-- <Parameter name="ProvisioningDefaultUserstore">PRIMARY</Parameter> --> 
            <!-- <Parameter name="ProvisioningDefaultRole">admin</Parameter> --> 
            <!-- <Parameter name="IsSuperAdminRoleRequired">true</Parameter> --> 
        </Config> 
   
  -4 Now you can deploy the "saml2.sso.demo.war" in to tomcat's webapps folder. 

  -5 Start the both IS and tomcat. 

  -6 you can use the "http://localhost:8080/saml2.sso.demo/" to test the web app " 


[1] https://docs.wso2.com/display/IS500/Working+with+Single+Sign-On
[2] http://wso2.com/library/articles/2010/07/saml2-web-browser-based-sso-wso2-identity-server/
