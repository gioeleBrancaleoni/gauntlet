// Gauntlet — ZAP script-based authentication for token / JSON login.
//
// Engine: ZAP script engine (Nashorn / Graal.js, as in ZAP's bundled
// scriptBasedAuthentication templates).
//
// What it does
// ------------
// Performs a token/JSON login: POSTs the credentials as a JSON body to the
// configured login URL, extracts the bearer token from the JSON response
// following a dot-path (e.g. "data.token"), and sets
//   Authorization: Bearer <token>
// on the authenticated request so ZAP scans the API as the logged-in user.
//
// Parameters (see getRequiredParamsNames / getOptionalParamsNames):
//   loginUrl       — absolute URL of the login endpoint
//   usernameField  — JSON field name for the username/email
//   passwordField  — JSON field name for the password
//   tokenPath      — dot-path to the token in the JSON response (optional;
//                    default "token")
//
// Credentials (see getCredentialsParamsNames) are supplied by ZAP's
// authentication-credentials mechanism (per context user), NOT hardcoded here.
//
// SECURITY: this script never logs the credentials or the extracted token.
// The only diagnostics emitted are non-sensitive status messages. Keeping the
// token out of ZAP's script/output log avoids leaking it to a persistent file.

var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");

// Walk a dot-path (e.g. "data.token") inside a parsed JSON object.
// Returns the value, or null if any segment is missing / not an object.
function extractToken(root, dottedPath) {
    var current = root;
    var segments = dottedPath.split(".");
    for (var i = 0; i < segments.length; i++) {
        if (current === null || typeof current !== "object") {
            return null;
        }
        current = current[segments[i]];
        if (current === undefined) {
            return null;
        }
    }
    return current;
}

function authenticate(helper, paramsValues, credentials) {
    print("Gauntlet token-auth: authenticating (token not logged)...");

    var loginUrl = paramsValues.get("loginUrl");
    var usernameField = paramsValues.get("usernameField");
    var passwordField = paramsValues.get("passwordField");
    var tokenPath = paramsValues.get("tokenPath");
    if (tokenPath === null || tokenPath === "") {
        tokenPath = "token";
    }

    var username = credentials.getParam("username");
    var password = credentials.getParam("password");

    // Build the JSON login request body from the configured field names.
    var body = {};
    body[usernameField] = username;
    body[passwordField] = password;
    var requestBody = JSON.stringify(body);

    var requestUri = new URI(loginUrl, false);
    var requestHeader = new HttpRequestHeader(
        HttpRequestHeader.POST, requestUri, HttpHeader.HTTP11);
    requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/json");

    var msg = helper.prepareMessage();
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    helper.sendAndReceive(msg);

    // Extract the token from the JSON response and inject it as a Bearer header
    // on the authenticated message. The Replacer rule added by build_zap_context
    // is what carries the header on subsequent scan requests.
    var responseText = msg.getResponseBody().toString();
    var token = null;
    try {
        var parsed = JSON.parse(responseText);
        token = extractToken(parsed, tokenPath);
    } catch (e) {
        print("Gauntlet token-auth: login response was not valid JSON.");
    }

    if (token === null || token === undefined || token === "") {
        print("Gauntlet token-auth: token not found at the configured path.");
    } else {
        // Set the Authorization header on the authenticated message. The
        // Replacer rule added by build_zap_context carries the token on
        // subsequent (scan) requests.
        msg.getRequestHeader().setHeader(
            HttpHeader.AUTHORIZATION, "Bearer " + token);
    }

    return msg;
}

function getRequiredParamsNames() {
    return ["loginUrl", "usernameField", "passwordField"];
}

function getOptionalParamsNames() {
    return ["tokenPath"];
}

function getCredentialsParamsNames() {
    return ["username", "password"];
}
