<?php
        require_once 'csrf.php';

// [Session Management 7.4: Properly unsetting + destroying session data on logout]
        session_unset();
        session_destroy();
        header("Location: ../logout.php");
        exit();
?>