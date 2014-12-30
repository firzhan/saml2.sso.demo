/**
 *  Copyright (c) 2014 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.identity.saml2.utils;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.authenticator.saml2.sso.stub.SAML2SSOAuthenticationServiceStub;
import org.wso2.carbon.identity.authenticator.saml2.sso.stub.types.AuthnReqDTO;
import org.wso2.carbon.user.mgt.stub.UserAdminStub;
import org.wso2.carbon.user.mgt.stub.UserAdminUserAdminException;
import org.wso2.identity.saml2.constants.SAML2Constants;
import org.wso2.identity.saml2.exception.SAMLProcessingException;

import java.rmi.RemoteException;
import java.util.Random;

import javax.servlet.ServletConfig;

public class Util {

    private static Log log = LogFactory.getLog(Util.class);

	/**
     * Generates a unique Id for Authentication Requests
     *
     * @return generated unique ID
     */
    public static String createID() {

        byte[] bytes = new byte[20]; // 160 bit
        
        new Random().nextBytes(bytes);
        
        char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

        char[] chars = new char[40];

        for (int i = 0; i < bytes.length; i++) {
            int left = (bytes[i] >> 4) & 0x0f;
            int right = bytes[i] & 0x0f;
            chars[i * 2] = charMapping[left];
            chars[i * 2 + 1] = charMapping[right];
        }

        return String.valueOf(chars);
    }
    
    /**
     * reads configurations from web.xml
     * @param servletConfig
     * @param configuration
     * @return
     */
    public static String getConfiguration(ServletConfig servletConfig, String configuration){
    	return servletConfig.getInitParameter(configuration);
		
    }

    /**
     * Obtains cookie for given SAML response message
     *
     * @param encodedSAMLResponse SAML response message
     * @param backendServerURL   back end IS url
     * @return
     * @throws Exception
     */
    public static String authenticateWithSAML2Response(String encodedSAMLResponse,String backendServerURL ) throws
            SAMLProcessingException {

        SAML2SSOAuthenticationServiceStub stub = null;

        try {

            stub = new SAML2SSOAuthenticationServiceStub( backendServerURL + SAML2Constants.SSO_AUTHENTICATOR_SERVICE);
            AuthnReqDTO authnReqDTO = new AuthnReqDTO();
            authnReqDTO.setResponse(encodedSAMLResponse);
            ServiceClient client = stub._getServiceClient();
            Options options = client.getOptions();
            options.setManageSession(true);

            boolean logged_in = stub.login(authnReqDTO);
            if (logged_in) {
                String cookie = (String) stub._getServiceClient().
                        getServiceContext().getProperty(HTTPConstants.COOKIE_STRING);
                return cookie;
            } else {
                throw new SAMLProcessingException("Login failure.");
            }
        } catch (AxisFault axisFault) {
            throw new SAMLProcessingException("Error thrown from SAML2SSOAuthenticationServiceStub ", axisFault);
        } catch (RemoteException e) {
            throw new SAMLProcessingException("Error thrown due to login failure in " +
                    "SAML2SSOAuthenticationServiceStub", e);
        } finally {
            if (stub != null) {
                try {
                    stub.cleanup();
                } catch (AxisFault axisFault) {
                    log.error("stub clean up operation failed ", axisFault);
                }
            }

        }
    }

    /**
     * Change the password of a logged-in user
     * @param cookie         cookie
     * @param oldPassword    current password
     * @param newPassword    new password
     * @throws SAMLProcessingException  in the event of operation failed
     */
    public static void changePasswordByUser(String cookie, String oldPassword,
                                      String newPassword) throws SAMLProcessingException{

        String targetEndpoint = SAML2Constants.SERVICES_URL + SAML2Constants.USER_ADMIN_SERVICE;

        UserAdminStub userAdminStub;
        try {
            userAdminStub = new UserAdminStub( targetEndpoint);
        } catch (AxisFault axisFault) {
            throw new SAMLProcessingException("userAdminStub creation failed", axisFault);
        }
        ServiceClient client = userAdminStub._getServiceClient();
        Options options = client.getOptions();
        options.setManageSession(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
        try {
            userAdminStub.changePasswordByUser(oldPassword, newPassword);
        } catch (RemoteException e) {
            throw new SAMLProcessingException("Remote invocation failed", e);
        } catch (UserAdminUserAdminException e) {
            throw new SAMLProcessingException("User Log in failed", e);
        }
    }


}
