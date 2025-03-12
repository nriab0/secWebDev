<?php
function escapeSTR($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}
