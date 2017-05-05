package com.kineticdata.bridgehub.adapter.amazonecs;

import com.kineticdata.bridgehub.adapter.BridgeAdapter;
import com.kineticdata.bridgehub.adapter.BridgeError;
import com.kineticdata.bridgehub.adapter.BridgeRequest;
import com.kineticdata.bridgehub.adapter.BridgeUtils;
import com.kineticdata.bridgehub.adapter.Count;
import com.kineticdata.bridgehub.adapter.Record;
import com.kineticdata.bridgehub.adapter.RecordList;
import com.kineticdata.bridgehub.adapter.amazonec2.v2.AmazonEC2Adapter;
import com.kineticdata.commons.v1.config.ConfigurableProperty;
import com.kineticdata.commons.v1.config.ConfigurablePropertyMap;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.*;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.slf4j.LoggerFactory;


public class AmazonEcsAdapter implements BridgeAdapter {
    /*----------------------------------------------------------------------------------------------
     * PROPERTIES
     *--------------------------------------------------------------------------------------------*/
    
    /** Defines the adapter display name */
    public static final String NAME = "Amazon ECS Bridge";
    
    /** Defines the logger */
    protected static final org.slf4j.Logger logger = LoggerFactory.getLogger(AmazonEcsAdapter.class);
    
    /** Adapter version constant. */
    public static String VERSION;
    /** Load the properties version from the version.properties file. */
    static {
        try {
            java.util.Properties properties = new java.util.Properties();
            properties.load(AmazonEcsAdapter.class.getResourceAsStream("/"+AmazonEcsAdapter.class.getName()+".version"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            logger.warn("Unable to load "+AmazonEcsAdapter.class.getName()+" version properties.", e);
            VERSION = "Unknown";
        }
    }
    
    /** Defines the collection of property names for the adapter */
    public static class Properties {
        public static final String ACCESS_KEY = "Access Key";
        public static final String SECRET_KEY = "Secret Key";
        public static final String REGION = "Region";
        public static final String API_VERSION = "API Version";
    }
    
    private final ConfigurablePropertyMap properties = new ConfigurablePropertyMap(
        new ConfigurableProperty(Properties.ACCESS_KEY).setIsRequired(true),
        new ConfigurableProperty(Properties.SECRET_KEY).setIsRequired(true).setIsSensitive(true),
        new ConfigurableProperty(Properties.REGION).setIsRequired(true)
    );
    
    private String accessKey;
    private String secretKey;
    private String region;
        
    /**
     * Structures that are valid to use in the bridge
     */
    public static final List<String> VALID_STRUCTURES = Arrays.asList(new String[] {
        "Clusters","ContainerInstances","Tasks"
    });
    
    /*---------------------------------------------------------------------------------------------
     * SETUP METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public void initialize() throws BridgeError {
        this.accessKey = properties.getValue(Properties.ACCESS_KEY);
        this.secretKey = properties.getValue(Properties.SECRET_KEY);
        this.region = properties.getValue(Properties.REGION);
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public String getVersion() {
        return VERSION;
    }
    
    @Override
    public void setProperties(Map<String,String> parameters) {
        properties.setValues(parameters);
    }
    
    @Override
    public ConfigurablePropertyMap getProperties() {
        return properties;
    }
    
    /*---------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public Count count(BridgeRequest request) throws BridgeError {
        String structure = request.getStructure();
        
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }
        
        AmazonEcsQualificationParser parser = new AmazonEcsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());
        
        // Build the response structure key identifier by lowercase the first letter of the structure
        String structureKeyIdentifier = structure.substring(0, 1).toLowerCase().concat(structure.substring(1,structure.length()-1));
        
        // Make the call to ECS to retrieve the Arns matching the query
        JSONObject arnsJson = ecsRequest("List"+structure,query);
        JSONArray structureArns = (JSONArray)arnsJson.get(structureKeyIdentifier.concat("Arns"));
        
        return new Count(structureArns.size());
    }

    @Override
    public Record retrieve(BridgeRequest request) throws BridgeError {
        String structure = request.getStructure();
        
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }
        
        AmazonEcsQualificationParser parser = new AmazonEcsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());
        
        // Build the response structure key identifier by lowercase the first letter of the structure
        String structureKeyIdentifier = structure.substring(0, 1).toLowerCase().concat(structure.substring(1,structure.length()-1));
        
        // Make the call to ECS to retrieve the Arns matching the query
        JSONObject arnsJson = ecsRequest("List"+structure,query);
        
        // Parse through and retrieve the structure Arns that match the query
        List<String> structureArns = new ArrayList<String>();
        JSONArray structureArnsXml = (JSONArray)arnsJson.get(structureKeyIdentifier.concat("Arns"));
        for (Object o : structureArnsXml) {
            structureArns.add(o.toString());
        }
        
        List<Record> records = new ArrayList<Record>();
        if (!structureArns.isEmpty()) {
            // Retrieve the cluster from the original query to append to the describe query (if it was
            // originally included)
            String cluster = null;
            if (!structure.equals("Clusters")) {
                Matcher m = Pattern.compile("cluster=(.*?)(?:&|\\z)").matcher(query);
                if (m.find()) cluster = m.group(1);
            }

            // Make the call to ECS retrieve the record objects for the returned Arns
            StringBuilder describeQuery = new StringBuilder();
            describeQuery.append(structureKeyIdentifier).append("s=[").append(StringUtils.join(structureArns,",")).append("]");
            if (cluster != null) describeQuery.append("&cluster=").append(cluster);
            JSONObject describeJson = ecsRequest("Describe"+structure,describeQuery.toString());
            // Parse through the response JSON to build record objects
            JSONArray structureObjs = (JSONArray)describeJson.get(structureKeyIdentifier.concat("s"));
            for (Object o : structureObjs) {
                records.add(new Record((Map)o));
            }
        }
        records = BridgeUtils.getNestedFields(request.getFields(), records);
        
        Record record;
        if (records.size() > 1) {
            throw new BridgeError("Multiple results matched an expected single match query");
        } else if (records.isEmpty()) {
            record = new Record(null);
        } else {
            if (request.getFields() == null || request.getFields().isEmpty()) {
                record = records.get(0);
            } else {
                Map<String,Object> recordObject = new LinkedHashMap<String,Object>();
                for (String field : request.getFields()) {
                    recordObject.put(field, records.get(0).getValue(field));
                }
                record = new Record(recordObject);
            }
        }
        
        return record;
    }

    @Override
    public RecordList search(BridgeRequest request) throws BridgeError {
        String structure = request.getStructure();
        
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }
        
        AmazonEcsQualificationParser parser = new AmazonEcsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());
        
        // Build the response structure key identifier by lowercase the first letter of the structure
        String structureKeyIdentifier = structure.substring(0, 1).toLowerCase().concat(structure.substring(1,structure.length()-1));
        
        // Make the call to ECS to retrieve the Arns matching the query
        JSONObject arnsJson = ecsRequest("List"+structure,query);
        
        // Parse through and retrieve the structure Arns that match the query
        List<String> structureArns = new ArrayList<String>();
        JSONArray structureArnsXml = (JSONArray)arnsJson.get(structureKeyIdentifier.concat("Arns"));
        for (Object o : structureArnsXml) {
            structureArns.add(o.toString());
        }
        
        List<Record> records = new ArrayList<Record>();
        if (!structureArns.isEmpty()) {
            // Retrieve the cluster from the original query to append to the describe query (if it was
            // originally included)
            String cluster = null;
            if (!structure.equals("Clusters")) {
                Matcher m = Pattern.compile("cluster=(.*?)(?:&|\\z)").matcher(query);
                if (m.find()) cluster = m.group(1);
            }

            // Make the call to ECS retrieve the record objects for the returned Arns
            StringBuilder describeQuery = new StringBuilder();
            describeQuery.append(structureKeyIdentifier).append("s=[").append(StringUtils.join(structureArns,",")).append("]");
            if (cluster != null) describeQuery.append("&cluster=").append(cluster);
            JSONObject describeJson = ecsRequest("Describe"+structure,describeQuery.toString());
            // Parse through the response JSON to build record objects
            JSONArray structureObjs = (JSONArray)describeJson.get(structureKeyIdentifier.concat("s"));
            for (Object o : structureObjs) {
                records.add(new Record((Map)o));
            }
            
            if (request.getFields() != null && !request.getFields().isEmpty()) records = addOtherStructureFields(request.getFields(),records,cluster);
            
        }
        
        // Define the fields - if not fields were passed, set they keySet of the a returned objects as
        // the field set
        List<String> fields = request.getFields();
        if ((fields == null || fields.isEmpty()) && !records.isEmpty()) fields = new ArrayList<String>(records.get(0).getRecord().keySet());
        
        // Define the metadata
        Map<String,String> metadata = new LinkedHashMap<String,String>();
        metadata.put("size",String.valueOf(records.size()));
        metadata.put("nextPageToken",null);
        
        records = BridgeUtils.getNestedFields(fields, records);

        // Returning the response
        return new RecordList(fields, records, metadata);
    }
    
    /*----------------------------------------------------------------------------------------------
     * HELPER METHODS
     *--------------------------------------------------------------------------------------------*/
    
    private JSONObject ecsRequest(String action, String query) throws BridgeError {
        // Build up the request query into a JSON object
        Map<String,Object> jsonQuery = new HashMap<String,Object>();
        if (query != null && !query.isEmpty()) {
            for (String part : query.split("&")) {
                String[] keyValue = part.split("=");
                String key = keyValue[0].trim();
                String value = keyValue[1].trim();
                // If the value is surrounded by [ ] it should be turned into a string list
                if (value.startsWith("[") && value.endsWith("]")) {
                    jsonQuery.put(key,Arrays.asList(value.substring(1,value.length()-1).split(",")));
                } else {
                    jsonQuery.put(key,value);
                }
            }
        }
        
        // The headers that we want to add to the request
        List<String> headers = new ArrayList<String>();
        headers.add("Content-Type: application/x-amz-json-1.1");
        headers.add("x-amz-target: AmazonEC2ContainerServiceV20141113."+action);
        
        // Make the request using the built up url/headers and bridge properties
        HttpResponse response = request("POST","https://ecs."+this.region+".amazonaws.com",headers,this.region,"ecs",JSONValue.toJSONString(jsonQuery),this.accessKey,this.secretKey);
        String output;
        try {
            output = EntityUtils.toString(response.getEntity());
        } catch (IOException e) { throw new BridgeError(e); }
        
        JSONObject json = (JSONObject)JSONValue.parse(output);
        if (json.containsKey("__type")) {
            logger.error(output);
            StringBuilder errorMessage = new StringBuilder("Error retrieving ECS records (See logs for more details)");
            errorMessage.append(" -- Type: ").append(json.get("__type").toString());
            if (json.containsKey("Message")) errorMessage.append(" -- Message: ").append(json.get("Message").toString());
            throw new BridgeError(errorMessage.toString());
        }
        
        return json;
    }
    
    private List<Record> addOtherStructureFields(List<String> fields, List<Record> records, String cluster) throws BridgeError {
        // Build hash of arns that should be returned from other structures
        Map<String,Map<String,Object>> complexObjects = new HashMap<String,Map<String,Object>>();
        
        // Find any complex fields
        Map<String,List<String>> complexFields = new HashMap<String,List<String>>();
        Pattern pattern = Pattern.compile("(.*?)\\.(.*?)\\z");
        for (String field : fields) {
            Matcher m = pattern.matcher(field);
            if (m.find()) {
                if (complexFields.containsKey(m.group(1))) {
                    complexFields.get(m.group(1)).add(m.group(2));
                } else {
                    complexFields.put(m.group(1), Arrays.asList(m.group(2)));
                    complexObjects.put(m.group(1),new HashMap<String,Object>());
                }
            }
        }

        if (!complexFields.isEmpty()) {
            // Retrieve the arns for the complex fields that need to be called
            Set<String> complexKeys = complexFields.keySet();
            for (Record record :records) {
                for (String key : complexKeys) {
                    String arn;
                    if (key.equals("instance")) {
                        arn = (String)record.getValue("ec2InstanceId");
                    } else {
                        arn = (String)record.getValue(key.concat("Arn"));
                    }
                    if (!complexObjects.get(key).keySet().contains(arn)) complexObjects.get(key).put(arn,null);
                }
            }
            
            // Make the calls to the different structures and populate the complexObject field
            // with the object corresponding to each arn
            for (Map.Entry<String,List<String>> entry : complexFields.entrySet()) {
                // Convert structure from containerInstance to DescribeContainerInstances (as an example)
                StringBuilder action = new StringBuilder("Describe");
                action.append(entry.getKey().substring(0,1).toUpperCase());
                action.append(entry.getKey().substring(1)).append("s");
                // Build query
                StringBuilder complexQuery = new StringBuilder();
                complexQuery.append(entry.getKey()).append("s=[");
                complexQuery.append(StringUtils.join(complexObjects.get(entry.getKey()).keySet(),","));
                complexQuery.append("]");
                if (cluster != null) complexQuery.append("&cluster=").append(cluster);
                JSONObject complexJson = ecsRequest(action.toString(),complexQuery.toString());
                JSONArray complexObjs = (JSONArray)complexJson.get(entry.getKey().concat("s"));
                for (Object o : complexObjs) {
                    JSONObject json = (JSONObject)o;
                    String arn = (String)json.get(entry.getKey().concat("Arn"));
                    complexObjects.get(entry.getKey()).put(arn,json);
                }
            }
            
            // Retrieve the objects related to the complex fields based on the corresponding Arn
            for (Record record : records) {
                for (Map.Entry<String,List<String>> entry : complexFields.entrySet()) {
                    for (String complexField : entry.getValue()) {
                        String arn = record.getValue(entry.getKey().concat("Arn")).toString();
                        JSONObject json = (JSONObject)complexObjects.get(entry.getKey()).get(arn);
                        record.getRecord().put(entry.getKey()+"."+complexField,json.get(complexField));
                    }
                }
            }
        }
        
        return records;
    }
    
    /**
     * This method builds and sends a request to the Amazon EC2 REST API given the inputted
     * data and return a HttpResponse object after the call has returned. This method mainly helps with
     * creating a proper signature for the request (documentation on the Amazon REST API signing
     * process can be found here - http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html),
     * but it also throws and logs an error if a 401 or 403 is retrieved on the attempted call.
     * 
     * @param url
     * @param headers
     * @param region
     * @param accessKey
     * @param secretKey
     * @return
     * @throws BridgeError 
     */
    private HttpResponse request(String method, String url, List<String> headers, String region, String service, String payload, String accessKey, String secretKey) throws BridgeError {
        // Build a datetime timestamp of the current time (in UTC). This will be sent as a header
        // to Amazon and the datetime stamp must be within 5 minutes of the time on the
        // recieving server or else the request will be rejected as a 403 Forbidden
        DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String datetime = df.format(new Date());
        String date = datetime.split("T")[0];
        
        // Create a URI from the request URL so that we can pull the host/path/query from it
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new BridgeError("There was an error parsing the inputted url '"+url+"' into a java URI.",e);
        }
        
        /* BUILD CANONCIAL REQUEST (uri, query, headers, signed headers, hashed payload)*/
        
        // Canonical URI (the part of the URL between the host and the ?. If blank, the uri is just /)
        String canonicalUri = uri.getPath().isEmpty() ? "/" : uri.getPath();
        
        // Canonical Query (parameter names sorted by asc and param names and values escaped
        // and trimmed)
        String canonicalQuery;
        // Trim the param names and values and load the parameters into a map
        Map<String,String> queryMap = new HashMap<String,String>();
        if (uri.getQuery() != null) {
            for (String parameter : uri.getQuery().split("&")) {
                queryMap.put(parameter.split("=")[0].trim(), parameter.split("=")[1].trim());
            }
        }
        
        StringBuilder queryBuilder = new StringBuilder();
        for (String key : new TreeSet<String>(queryMap.keySet())) {
            if (!queryBuilder.toString().isEmpty()) queryBuilder.append("&");
            queryBuilder.append(URLEncoder.encode(key)).append("=").append(URLEncoder.encode(queryMap.get(key)));
        }
        canonicalQuery = queryBuilder.toString();
        
        // Canonical Headers (lowercase and sort headers, add host and date headers if they aren't
        // already included, then create a header string with trimmed name and values and a new line
        // character after each header - including the last one)
        String canonicalHeaders;
        // Lowercase/trim each header and header value and load into a map
        Map<String,String> headerMap = new HashMap<String,String>();
        for (String header : headers) {
            headerMap.put(header.split(":")[0].toLowerCase().trim(), header.split(":")[1].trim());
        }
        // If the date and host headers aren't already in the header map, add them
        if (!headerMap.keySet().contains("host")) headerMap.put("host",uri.getHost());
        if (!headerMap.keySet().contains("x-amz-date")) headerMap.put("x-amz-date",datetime);
        // Sort the headers and append a newline to the end of each of them
        StringBuilder headerBuilder = new StringBuilder();
        for (String key : new TreeSet<String>(headerMap.keySet())) {
            headerBuilder.append(key).append(":").append(headerMap.get(key)).append("\n");
        }
        canonicalHeaders = headerBuilder.toString();
        
        // Signed Headers (a semicolon separated list of heads that were signed in the previous step)
        String signedHeaders = StringUtils.join(new TreeSet<String>(headerMap.keySet()),";");
        
        // Hashed Payload (a SHA256 hexdigest with the request payload - because the bridge only
        // does GET requests the payload will always be an empty string)
        String hashedPayload = DigestUtils.sha256Hex(payload);
        
        // Canonical Request (built out of 6 parts - the request method and the previous 5 steps in order
        // - with a newline in between each step and then a SHA256 hexdigest run on the resulting string)
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append(method).append("\n");
        requestBuilder.append(canonicalUri).append("\n");
        requestBuilder.append(canonicalQuery).append("\n");
        requestBuilder.append(canonicalHeaders).append("\n");
        requestBuilder.append(signedHeaders).append("\n");
        requestBuilder.append(hashedPayload);
        
        logger.debug(requestBuilder.toString());
        // Run the resulting string through a SHA256 hexdigest
        String canonicalRequest = DigestUtils.sha256Hex(requestBuilder.toString());
        
        /* BUILD STRING TO SIGN (credential scope, string to sign) */
        
        // Credential Scope (date, region, service, and terminating string [which is always aws4_request)
        String credentialScope = String.format("%s/%s/%s/aws4_request",date,region,service);
        
        // String to Sign (encryption method, datetime, credential scope, and canonical request)
        StringBuilder stringToSignBuilder = new StringBuilder();
        stringToSignBuilder.append("AWS4-HMAC-SHA256").append("\n");
        stringToSignBuilder.append(datetime).append("\n");
        stringToSignBuilder.append(credentialScope).append("\n");
        stringToSignBuilder.append(canonicalRequest);
        logger.debug(stringToSignBuilder.toString());
        String stringToSign = stringToSignBuilder.toString();
        
        /* CREATE THE SIGNATURE (signing key, signature) */
        
        // Signing Key
        byte[] signingKey;
        try {
            signingKey = getSignatureKey(secretKey,date,region,service);
        } catch (Exception e) {
            throw new BridgeError("There was a problem creating the signing key",e);
        }
        
        // Signature
        String signature;
        try {
            signature = Hex.encodeHexString(HmacSHA256(signingKey,stringToSign));
        } catch (Exception e) {
            throw new BridgeError("There was a problem creating the signature",e);
        }
        
        // Authorization Header (encryption method, access key, credential scope, signed headers, signature))
        String authorization = String.format("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",accessKey,credentialScope,signedHeaders,signature);
        
        /* CREATE THE HTTP REQUEST */
        HttpClient client = new DefaultHttpClient();
        HttpRequestBase request;
        try {
            if (method.toLowerCase().equals("get")) {
                request = new HttpGet(url);
            } else if (method.toLowerCase().equals("post")) {
                request = new HttpPost(url);
                ((HttpPost)request).setEntity(new StringEntity(payload));
            } else {
                throw new BridgeError("Http Method '"+method+"' is not supported");
            }
        } catch (UnsupportedEncodingException e) {
            throw new BridgeError(e);
        }

        request.setHeader("Authorization",authorization);
        for (Map.Entry<String,String> header : headerMap.entrySet()) {

            request.setHeader(header.getKey(),header.getValue());
        }
        
        HttpResponse response;
        try {
            response = client.execute(request);
            
            if (response.getStatusLine().getStatusCode() == 401 || response.getStatusLine().getStatusCode() == 403) {
                logger.error(EntityUtils.toString(response.getEntity()));
                throw new BridgeError("User not authorized to access this resource. Check the logs for more details.");
            }
        } catch (IOException e) { throw new BridgeError(e); }
        
        return response;
    }
    
    static byte[] HmacSHA256(byte[] key, String data) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    static byte[] getSignatureKey(String secretKey, String date, String region, String service) throws Exception  {
         byte[] kSecret = ("AWS4" + secretKey).getBytes("UTF8");
         byte[] kDate    = HmacSHA256(kSecret, date);
         byte[] kRegion  = HmacSHA256(kDate, region);
         byte[] kService = HmacSHA256(kRegion, service);
         byte[] kSigning = HmacSHA256(kService, "aws4_request");
         return kSigning;
    }
 
}