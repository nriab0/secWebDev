<?php
//ensure session is started (anti-redundant)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

//generate CSRF token only if it's missing
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

//to insert CSRF token into forms
function csrf_input() {
    return '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
}

//validate CSRF token on form submission
function csrf_validate() {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF validation failed. Session Token: " . $_SESSION['csrf_token'] . " | Submitted Token: " . $_POST['csrf_token']);
    }
}
?>
