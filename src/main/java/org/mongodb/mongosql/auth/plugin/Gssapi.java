/*
 * Copyright 2008-2017 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.mongodb.mongosql.auth.plugin;

import org.ietf.jgss.*;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.util.HashMap;
import java.util.Map;

final class Gssapi {
    private static final String SERVICE_NAME_DEFAULT_VALUE = "mongosql";
    private static final String GSSAPI_OID = "1.2.840.113554.1.2.2";

    static SaslClient createSaslClient(final String user, final String hostName) throws SaslException {

        GSSCredential clientCreds = getGSSCredential(user);

        try {
            GSSManager manager = GSSManager.getInstance();
            GSSName serviceName = manager.createName(SERVICE_NAME_DEFAULT_VALUE + "@" + hostName, GSSName.NT_HOSTBASED_SERVICE);

            GSSContext context = manager.createContext(serviceName, new Oid(GSSAPI_OID), clientCreds, GSSContext.DEFAULT_LIFETIME);
            return new GssapiSaslClient(context);

        } catch (GSSException e) {
            throw new SaslException("Error creating GSSAPI context", e);
        }
    }

    private static GSSCredential getGSSCredential(final String userName) throws SaslException {
        try {
            Oid krb5Mechanism = new Oid(GSSAPI_OID);
            GSSManager manager = GSSManager.getInstance();
            GSSName name = manager.createName(userName, GSSName.NT_USER_NAME);
            return manager.createCredential(name, GSSCredential.INDEFINITE_LIFETIME, krb5Mechanism, GSSCredential.INITIATE_ONLY);
        } catch (GSSException e) {
            throw new SaslException("Unable to create GSSAPI credential", e);
        }
    }

    private static class GssapiSaslClient implements SaslClient {

        private GSSContext context;

        GssapiSaslClient(GSSContext context) {
            this.context = context;
        }

        @Override
        public String getMechanismName() {
            return "GSSAPI";
        }

        @Override
        public boolean hasInitialResponse() {
            return false;
        }

        @Override
        public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
            try {
                return context.initSecContext(challenge, 0 , challenge.length);
            } catch (GSSException e) {
                throw new SaslException("Error initiating GSS context", e);
            }
        }

        @Override
        public boolean isComplete() {
            return context.isEstablished();
        }

        @Override
        public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public Object getNegotiatedProperty(String propName) {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public void dispose() throws SaslException {
            try {
                context.dispose();
            } catch (GSSException e) {
                throw new SaslException("Error disposing GSS context", e);
            }
        }
    }
}
