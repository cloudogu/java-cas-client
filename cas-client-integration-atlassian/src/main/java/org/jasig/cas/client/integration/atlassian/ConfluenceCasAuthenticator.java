/**
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.client.integration.atlassian;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.exception.DirectoryNotFoundException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.manager.directory.DirectoryManager;
import com.atlassian.sal.api.component.ComponentLocator;
import com.atlassian.seraph.auth.AuthenticatorException;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.validation.Assertion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.sql.Date;

/**
 * Extension of ConfluenceAuthenticator to allow people to configure Confluence to authenticate
 * via CAS.
 *
 * @author Scott Battaglia
 * @author John Watson
 * @version $Revision$ $Date$
 * @since 3.1.2
 */
public final class ConfluenceCasAuthenticator extends ConfluenceAuthenticator {

    /**
     * ConfluenceCasAuthenticator.java
     */
    private static final long serialVersionUID = -6097438206488390677L;

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfluenceCasAuthenticator.class);

    public Principal getUser(final HttpServletRequest request, final HttpServletResponse response) {
        final HttpSession session = request.getSession();

        // user already exists
        if (session.getAttribute(LOGGED_IN_KEY) != null) {
            LOGGER.debug("Session found; user already logged in.");
            return (Principal) session.getAttribute(LOGGED_IN_KEY);
        }

        final Assertion assertion = (Assertion) session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION);

        if (assertion != null) {
            final String username = assertion.getPrincipal().getName();
            final Principal user = getUser(username);

            // user doesn't exist
            if (user == null) {
                try {
                    // The user wasn't found in confluence but is authenticated with cas.
                    // Maybe the user was created after the last directory synchronization.
                    synchronizeUsers();
                } catch (OperationFailedException | DirectoryNotFoundException e) {
                    e.printStackTrace();
                }
                LOGGER.error("Could not determine principal for [{}]", assertion.getPrincipal().getName());
                getElevatedSecurityGuard().onFailedLoginAttempt(request, username);
                return null;
            }

            LOGGER.debug("Logging in [{}] from CAS.", username);

            getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, username);
            session.setAttribute(LOGGED_IN_KEY, user);
            session.setAttribute(LOGGED_OUT_KEY, null);
            return user;
        }

        return super.getUser(request, response);
    }

    static synchronized void synchronizeUsers() throws OperationFailedException, DirectoryNotFoundException {
        DirectoryManager directoryManager = ComponentLocator.getComponent(DirectoryManager.class);
        for (Directory directory : directoryManager.findAllDirectories()) {
            if (directoryManager.isSynchronisable(directory.getId())
                    && !directoryManager.isSynchronising(directory.getId())) {
                Date threshold = new Date(System.currentTimeMillis() - 30 * 1000);
                if (directory.getUpdatedDate().before(threshold)) {
                    LOGGER.debug("Synchronizing directory {}", directory.getName());
                    directoryManager.synchroniseCache(directory.getId(), directoryManager.getSynchronisationMode(directory.getId()), false);
                } else {
                    LOGGER.debug("Directory {} was synchronized in the last 30 seconds", directory.getName());
                }
            }
        }
    }

    public boolean logout(final HttpServletRequest request, final HttpServletResponse response)
            throws AuthenticatorException {
        final HttpSession session = request.getSession();

        final Principal principal = (Principal) session.getAttribute(LOGGED_IN_KEY);

        LOGGER.debug("Logging out [{}] from CAS.", principal.getName());

        session.setAttribute(LOGGED_OUT_KEY, principal);
        session.setAttribute(LOGGED_IN_KEY, null);
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION, null);
        return true;
    }
}
