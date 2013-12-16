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

module SunstoneX509CloudAuth
    def do_auth(env, params={})
        # For SSL X509 authN, the web service should be set to include the user cert DN in the environment.
        cert_dn   = env['HTTP_SSL_CLIENT_S_DN'] || env['SSL_CLIENT_S_DN']

        # Use the https credentials for authentication
        if cert_dn && !cert_dn.empty?
            # Password should be DN with whitespace chars removed.
            username = get_username(OpenNebula::X509Auth.escape_dn(cert_dn))
            return username if username
        else
            raise "Username not found in certificate chain "
        end

        return nil
    end
end
