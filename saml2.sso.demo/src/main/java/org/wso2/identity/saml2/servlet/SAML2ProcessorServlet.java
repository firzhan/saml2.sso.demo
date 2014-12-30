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

package org.wso2.identity.saml2.servlet;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.mgt.stub.UserAdminStub;
import org.wso2.carbon.user.mgt.stub.UserAdminUserAdminException;
import org.wso2.identity.saml2.constants.SAML2Constants;
import org.wso2.identity.saml2.exception.SAMLProcessingException;
import org.wso2.identity.saml2.utils.Util;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.rmi.RemoteException;


public class SAML2ProcessorServlet extends HttpServlet{

    private static Log log = LogFactory.getLog(SAML2ProcessorServlet.class);
    /**
     * Servlet init
     */
    public void init(ServletConfig config) throws ServletException {
        System.setProperty("javax.net.ssl.trustStore", "/home/firzhan/key-store/client-truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "wso2carbon");
        System.setProperty("javax.net.ssl.trustStoreType", "jks");
    }

    /**
     * @see HttpServlet#doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException,
            IOException {
        doPost(request, response);
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException {

        String responseMessage = (String) request.getSession().getAttribute(SAML2Constants.SAML_RESPONSE_ATTRIBUTE);
        String oldPassword = request.getParameter(SAML2Constants.SAML_OLD_PASSWORD);
        String newPassword = request.getParameter(SAML2Constants.SAML_NEW_PASSWORD);
        log.info("response " + responseMessage);
        try {
            String cookie = Util.authenticateWithSAML2Response(responseMessage, SAML2Constants.SERVICES_URL);
            Util.changePasswordByUser( cookie, oldPassword, newPassword);
            response.sendRedirect("index.jsp");
        } catch (SAMLProcessingException e){
            throw new ServletException(e.getMessage(), e);
        } catch (IOException e){
            throw new ServletException("Response redirection to index.jsp failed", e);
        }
    }




}
