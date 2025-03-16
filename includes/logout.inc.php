<?php
        require_once 'csrf.inc.php';


        session_unset();
        session_destroy();
        header("Location: ../logout.php");
        exit();
?>