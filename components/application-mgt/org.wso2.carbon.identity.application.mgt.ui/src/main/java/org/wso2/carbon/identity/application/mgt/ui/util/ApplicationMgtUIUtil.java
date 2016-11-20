/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.mgt.ui.util;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.xsd.Property;
import org.wso2.carbon.identity.application.mgt.ui.ApplicationBean;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

public class ApplicationMgtUIUtil {

    private static final String SP_UNIQUE_ID_MAP = "spUniqueIdMap";

    private static final String HMAC_SHA1 = "HmacSHA1";

    /**
     * Get related application bean from the session.
     *
     * @param session HTTP Session.
     * @param spName  Service provider name.
     * @return ApplicationBean
     */
    public static ApplicationBean getApplicationBeanFromSession(HttpSession session, String spName) {

        Map<String, UUID> spUniqueIdMap;

        if (session.getAttribute(SP_UNIQUE_ID_MAP) == null) {
            spUniqueIdMap = new HashMap<>();
            session.setAttribute(SP_UNIQUE_ID_MAP, spUniqueIdMap);
        } else {
            spUniqueIdMap = (HashMap<String, UUID>)session.getAttribute(SP_UNIQUE_ID_MAP);
        }

        if (spUniqueIdMap.get(spName) == null) {
            ApplicationBean applicationBean = new ApplicationBean();
            UUID uuid = UUID.randomUUID();
            spUniqueIdMap.put(spName, uuid);
            session.setAttribute(uuid.toString(), applicationBean);
        }
        return (ApplicationBean) session.getAttribute(spUniqueIdMap.get(spName).toString());
    }

    /**
     * Remove related application bean from the session.
     *
     * @param session Http Session.
     * @param spName  Service provider name.
     */
    public static void removeApplicationBeanFromSession(HttpSession session, String spName) {

        if (session.getAttribute(SP_UNIQUE_ID_MAP) == null) {
            return;
        }
        Map<String, UUID> spUniqueIdMap = (HashMap<String, UUID>)session.getAttribute(SP_UNIQUE_ID_MAP);

        if (spUniqueIdMap.get(spName) == null) {
            return;
        }
        session.removeAttribute(spUniqueIdMap.get(spName).toString());
        spUniqueIdMap.remove(spName);
    }

    public static Property[] sortProperties(Property[] unsortedProperties) {
        List<Property> propertyList = Arrays.asList(unsortedProperties);
        Collections.sort(propertyList, new PropertyComparator());
        return propertyList.toArray(new Property[propertyList.size()]);
    }

    public static class PropertyComparator implements Comparator<Property> {

        @Override
        public int compare(Property property1, Property property2) {
            if(property1.getDisplayOrder() > property2.getDisplayOrder()) {
                return 1;
            } else if(property1.getDisplayOrder() == property2.getDisplayOrder()) {
                return 0;
            } else {
                return -1;
            }
        }
    }

    /**
     * Generates a random number using two UUIDs and HMAC-SHA1
     *
     * @return generated secure random number
     * @throws Exception Invalid Algorithm or Invalid Key
     */
    public static String getRandomNumber() throws RuntimeException {
        try {
            String secretKey = UUIDGenerator.generateUUID();
            String baseString = UUIDGenerator.generateUUID();

            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(Charsets.UTF_8), HMAC_SHA1);
            Mac mac = Mac.getInstance(HMAC_SHA1);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(baseString.getBytes(Charsets.UTF_8));
            String random = Base64.encode(rawHmac);
            // Registry doesn't have support for these character.
            random = random.replace("/", "_");
            random = random.replace("=", "a");
            random = random.replace("+", "f");
            return random;
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while generating a random number.", e);
        }
    }

    public static List<String> extractSupportedGrantTypes(Property[] properties) {
        List<String> supportedGrantTypes = new ArrayList();
        for(Property property : properties) {
            if(safeStartsWith(property.getName(), "supported_grant_type")) {
                supportedGrantTypes.add(property.getDisplayName());
            }
        }
        return supportedGrantTypes;
    }

    public static List<String> extractAllowedGrantTypes(Property[] properties) {
        List<String> allowedGrantTypes = new ArrayList();
        for(Property property : properties) {
            if(safeStartsWith(property.getName(), "supported_grant_type")) {
                if(Boolean.parseBoolean((property.getValue()))) {
                    allowedGrantTypes.add(property.getDisplayName());
                }
            }
        }
        return allowedGrantTypes;
    }

    public static List<String> extractSupportedResponseTypes(Property[] properties) {
        List<String> supportedResponseTypes = new ArrayList();
        for(Property property : properties) {
            if(safeStartsWith(property.getName(), "supported_response_type")) {
                supportedResponseTypes.add(property.getDisplayName());
            }
        }
        return supportedResponseTypes;
    }

    public static List<String> extractAllowedResponseTypes(Property[] properties) {
        List<String> allowedResponseTypes = new ArrayList();
        for(Property property : properties) {
            if(safeStartsWith(property.getName(), "supported_response_type")) {
                if (Boolean.parseBoolean((property.getValue()))) {
                    allowedResponseTypes.add(property.getDisplayName());
                }
            }
        }
        return allowedResponseTypes;
    }

    public static boolean safeStartsWith(String input, String startsWith) {
        if(input != null && input.startsWith(startsWith)) {
            return true;
        }
        return false;
    }

    public static boolean safeContains(String input, String contains) {
        if(StringUtils.isNotBlank(input) && StringUtils.isNotBlank(contains)) {
            return input.contains(contains);
        }
        return false;
    }
}