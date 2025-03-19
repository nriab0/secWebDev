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

function csrf_validate() {
    if (!isset($_SESSION['csrf_token'])) {
        die("❌ CSRF validation failed: No session token found.");
    }

    if (!isset($_POST['csrf_token'])) {
        die("❌ CSRF validation failed: No token submitted.");
    }

    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("❌ CSRF validation failed. <br> Session Token: " . $_SESSION['csrf_token'] . " <br> Submitted Token: " . $_POST['csrf_token']);
    }
}

