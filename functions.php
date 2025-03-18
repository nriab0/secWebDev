<?php
function escapeSTR($input) {
    return htmlspecialchars(trim((string)$input), ENT_QUOTES, 'UTF-8');
}
