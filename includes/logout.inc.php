<?php
        require_once 'csrf.php';


        session_unset();
        session_destroy();
        header("Location: ../logout.php");
        exit();
?>