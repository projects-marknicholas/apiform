<?php

// index.php

// Basic routing logic
$request_uri = $_SERVER['REQUEST_URI'];

// Split the request URI to get the endpoint
$uri_parts = explode('/', $request_uri);

// Extract the endpoint from the URI
$endpoint = isset($uri_parts[2]) ? $uri_parts[2] : null;

// Include api.php to access API functions
include 'api.php';
// Include submission.php to access form submissions functions
include 'submission.php';

// Route requests to API functions based on the endpoint
if ($endpoint === 'register') {
    // Call the login function from api.php
    register();
} elseif ($endpoint === 'verify') {
    // Call the verifyAccount function from api.php
    verifyAccount();
} elseif ($endpoint === 'login') {
    // Call the login function from api.php
    login();
} elseif ($endpoint === 'forgot-password') {
    // Call the forgotPassword function from api.php
    forgotPassword();
} elseif (strpos($endpoint, 'reset-password') !== false) {
    // Extract tokenNumber from the endpoint
    $tokenNumber = end($uri_parts);
    
    // Call the resetPassword function from api.php
    resetPassword($tokenNumber);
} elseif (strpos($endpoint, 'send') !== false) {
    // Extract formToken from the endpoint
    $formToken = end($uri_parts);
    
    // Call the sendSubmission function from api.php
    sendSubmission($formToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'create-form' && isset($uri_parts[4])) {
	// Extract formToken from the endpoint
	$userToken = $uri_parts[4];
    // Call the createForm function from api.php
    createForm($userToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'update-form' && isset($uri_parts[4])) {
    // Extract formToken from the endpoint
    $formToken = $uri_parts[4];
    
    // Call the updateForm function from api.php
    updateForm($formToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'delete-form' && isset($uri_parts[4])) {
    // Extract formToken from the endpoint
    $formToken = $uri_parts[4];
    
    // Call the updateForm function from api.php
    deleteForm($formToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'read-all-user-form' && isset($uri_parts[4])) {
    // Extract userToken from the endpoint
    $userToken = $uri_parts[4];
    
    // Call the readForms function from api.php
    readForms($userToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'read-form-by-form-token' && isset($uri_parts[4]) && isset($uri_parts[5])) {
    // Extract userToken and formToken from the endpoint
    $userToken = $uri_parts[4];
    $formToken = $uri_parts[5];
    
    // Call the readFormsByFormToken function from api.php
    readFormsByFormToken($userToken, $formToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'create-email-server' && isset($uri_parts[4]) && isset($uri_parts[5])) {
    // Extract userToken and formToken from the endpoint
    $userToken = $uri_parts[4];
    $formToken = $uri_parts[5];
    
    // Call the createEmailServer function from api.php
    createEmailServer($userToken, $formToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'read-all-email-servers' && isset($uri_parts[4]) && isset($uri_parts[5])) {
    // Extract userToken and formToken from the endpoint
    $userToken = $uri_parts[4];
    $formToken = $uri_parts[5];

    // Call the readAllEmailServers function from api.php
    readAllEmailServers($userToken, $formToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'update-email-server' && isset($uri_parts[4]) && isset($uri_parts[5]) && isset($uri_parts[6])) {
    // Extract userToken, formToken, and serverToken from the endpoint
    $userToken = $uri_parts[4];
    $formToken = $uri_parts[5];
    $serverToken = $uri_parts[6];
    
    // Check if the status parameter is provided, otherwise, set it to null
    $status = isset($uri_parts[7]) ? $uri_parts[7] : null;
    
    // Call the updateEmailServer function from api.php
    updateEmailServer($userToken, $formToken, $serverToken, $status);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'delete-email-server' && isset($uri_parts[4]) && isset($uri_parts[5]) && isset($uri_parts[6])) {
    // Extract userToken, formToken, and server ID from the endpoint
    $userToken = $uri_parts[4];
    $formToken = $uri_parts[5];
    $serverToken = $uri_parts[6];
    
    // Call the deleteEmailServerById function from api.php
    deleteEmailServerByToken($userToken, $formToken, $serverToken);
} elseif ($endpoint === 'api' && isset($uri_parts[3]) && $uri_parts[3] === 'invitation' && isset($uri_parts[4]) && isset($uri_parts[5]) && isset($uri_parts[6])) {
    // Extract userToken, formToken, and server ID from the endpoint
    $userToken = $uri_parts[4];
    $formToken = $uri_parts[5];
    $serverToken = $uri_parts[6];
    
    // Call the sendInvitationEmailWithLink function from api.php
    sendInvitationEmailWithLink($userToken, $formToken, $serverToken);
} elseif ($endpoint === 'user') {
    // Call the user function from api.php
    user();
} else {
    // Send JSON response
    header('Content-Type: application/json');
    http_response_code(404);
    echo json_encode(array('message' => 'Endpoint not found'));
}
?>
