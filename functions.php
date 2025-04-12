<?php
// [Reflective / Persistent XSS 1.4 / 2.4: Safe HTML escaping to prevent script injection]
function escapeSTR($input) {
    return htmlspecialchars(trim((string)$input), ENT_QUOTES, 'UTF-8');
}

// Another sanitizer, for HTML input 
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}