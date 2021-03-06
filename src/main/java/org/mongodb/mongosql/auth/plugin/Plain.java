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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;

final class Plain {
    static SaslClient createSaslClient(final String user, final String password) throws SaslException {
        return Sasl.createSaslClient(new String[]{"PLAIN"}, user, null, null, null,
                new CallbackHandler() {
                    @Override
                    public void handle(final Callback[] callbacks)
                            throws IOException, UnsupportedCallbackException {
                        for (final Callback callback : callbacks) {
                            if (callback instanceof PasswordCallback) {
                                ((PasswordCallback) callback).setPassword(password.toCharArray());
                            } else if (callback instanceof NameCallback) {
                                ((NameCallback) callback).setName(user);
                            }
                        }
                    }
                });
    }

    private Plain() {}
}
