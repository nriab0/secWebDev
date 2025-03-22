<?php
// auth2.php

session_start();
require_once 'functions.php';
require_once 'csrf.php';
include_once 'header.php';

// -------------------------------------------------
// Redirect if the user is not logged in
// -------------------------------------------------
if (!isset($_SESSION['u_id'])) {
    header("Location: home.php");
    exit();
}

// Save session variables for later use
$user_id  = $_SESSION['u_id'];
$user_uid = $_SESSION['u_uid'];

// -------------------------------------------------
// Directory Traversal Prevention Measures
// -------------------------------------------------

// 1. Define a whitelist of allowed files
$allowedFiles = ['yellow.txt'];

// 2. Check if a file is specified in the URL via the GET parameter
if (!isset($_GET['FileToView'])) {
    die("No file specified.");
}

// 3. Sanitize the input by stripping any directory components
$ViewFile = basename($_GET['FileToView']);

// 4. Reject any input that contains parent directory traversal patterns
if (strpos($ViewFile, "..") !== false) {
    die("Invalid file request.");
}

// 5. Verify that the requested file is in the allowed list
if (!in_array($ViewFile, $allowedFiles)) {
    die("Unauthorized file access.");
}

// 6. Include the file that sets the safe file path
require_once 'paths.php';

// 7. Confirm that the safe path is set and the file exists
if (!isset($safePath) || !file_exists($safePath)) {
    die("File not found.");
}

// 8. Safely include the allowed file
include_once $safePath;

include_once 'footer.php';
?>
