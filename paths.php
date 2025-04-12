<?php
// paths.php

// [Mitigation for Directory Traversal 6.4: Define a safe base directory for file inclusion]
define("FILES_DIR", __DIR__ . "/pages");

// If $ViewFile is defined, build the safe absolute path for it
if (isset($ViewFile)) {
    $safePath = FILES_DIR . "/" . $ViewFile;
}
?>
