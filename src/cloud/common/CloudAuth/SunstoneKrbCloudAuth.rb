# -------------------------------------------------------------------------- #
# Copyright 2002-2013, OpenNebula Project (OpenNebula.org), C12G Labs        #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

require 'opennebula/x509_auth'

module SunstoneKrbCloudAuth
    def do_auth(env, params={})
        # For SSL KRB5 authN, the web service should be set to include the user principal in the environment.
        krb_principal   = env['REMOTE_USER']

        # Use krb credentials for authentication
        raise "Username not found in REMOTE_USER " if krb_principal.nil? || krb_principal.empty?
        raise "Username is malformed " unless krb_principal.include?('@') && (krb_principal.split('@').count == 2)

        # Password should be the principal with whitespace chars removed.
        username = get_username(OpenNebula::X509Auth.escape_dn(krb_principal))
        return username if username

        return nil
    end
end
