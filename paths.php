<?php
// paths.php

// Define the base directory where allowed files reside
define("FILES_DIR", __DIR__ . "/pages");

// If $ViewFile is defined, build the safe absolute path for it
if (isset($ViewFile)) {
    $safePath = FILES_DIR . "/" . $ViewFile;
}
?>
