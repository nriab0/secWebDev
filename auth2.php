<?php
require_once 'functions.php';
require_once 'csrf.php';
include_once 'header.php';

// Redirect non-logged in users
if (!isset($_SESSION['u_id'])) {
    header("Location: home.php");
    exit();
} else {
    $user_id = $_SESSION['u_id'];
    $user_uid = $_SESSION['u_uid'];
}

// --- Directory Traversal Prevention Measures ---

// 1. Define a list of allowed files
$allowedFiles = ['yellow.txt', 'log.txt', 'rules.txt'];

// 2. Sanitize user input (using our custom sanitizeInput function)
$ViewFile = sanitizeInput($_GET['FileToView']);

// 3. Prevent parent directory traversal
if (strpos($ViewFile, "..") !== false) {
    die("Invalid file request.");
}

// 4. Ensure the file is in the allowed list
if (!in_array($ViewFile, $allowedFiles)) {
    die("Unauthorized file access.");
}

// 5. Disallow PHP files to prevent remote code execution
if (pathinfo($ViewFile, PATHINFO_EXTENSION) === "php") {
    die("Execution of PHP files is not allowed.");
}

// 6. Use an absolute path (ensure the files are stored in a dedicated directory)
// Define the absolute path to the allowed files folder on your live server
define("FILES_DIR", "/var/www/html/yourproject/files");
$safePath = FILES_DIR . "/" . $ViewFile;

// 7. Read and output the file content securely
if (file_exists($safePath)) {
    $FileData = file_get_contents($safePath);
    // Output is sanitized to prevent XSS
    echo sanitizeInput($FileData);
} else {
    echo "No file found.";
}

include_once 'footer.php';
?>