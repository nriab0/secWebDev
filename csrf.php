<?php
// Generate CSRF token if missing
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = hash('sha256', random_bytes(64));
}

// Function to insert CSRF token into forms
function csrf_input() {
    return '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
}
?>