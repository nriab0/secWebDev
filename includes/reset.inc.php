<?php

//If user is not logged in or requesting to reset, redirect
include 'dbh.inc.php';
require_once 'functions.php';
require_once 'csrf.php';

if (!isset($_POST['reset'],$_SESSION['u_uid'])) {
    $_SESSION['resetError'] = "Error code 1";
    header("Location: ../index.php");
} else {

    //validate CSRF token
    csrf_validate();

    // Track brute-force attempts per session
    if (!isset($_SESSION['resetAttempts'])) {
        $_SESSION['resetAttempts'] = 0;
    }
    $_SESSION['resetAttempts']++;

    if ($_SESSION['resetAttempts'] > 3) {
        $_SESSION['resetError'] = "Too many failed attempts. Please try again later.";
        header("Location: ../index.php");
        exit();
    }

    $oldpass = $_POST['old'];
    $newConfirm = $_POST['new_confirm'];
    $newpass = $_POST['new'];

    // Validate Password (At least 8 characters, 1 uppercase, 1 lowercase, 1 digit)
    if (!preg_match('/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/', $newpass)) {
        $_SESSION['resetError'] = "Password must be at least 8 characters, include uppercase, lowercase, and a digit.";
        header("Location: ../index.php");
        exit();
    }
    

    if (empty($oldpass || $newpass)) {
        $_SESSION['resetError'] = "Error code 2";
    } else {
//u_uid was not sanitized, so it is vulnerable to SQL injection
        $uid = sanitizeInput($_SESSION['u_uid']);
        
        $checkOld = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
        $stmt = $conn->prepare($checkOld);
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) { 

            $row = mysqli_fetch_assoc($result); 

			//authenticate the old password
            //hash the old password with the salt from the database
            $saltFromDB = $row['user_salt'];
            $storedHash = $row['user_pwd'];
            $computedHash = hash('sha256', $saltFromDB . $oldpass);
            
            if ($newConfirm == $newpass) { // confirm they match
                $changePass = "UPDATE `sapusers` SET `user_pwd` = ? WHERE `user_uid` = ?";
                $stmt = $conn->prepare($changePass);
                
                $newHashed = hash('sha256', $saltFromDB . $newpass);  // ✅ Hash with same salt
            
                $stmt->bind_param("ss", $newHashed, $uid);  // ✅ Bind the hashed password
                
                $_SESSION['resetAttempts'] = 0;  // Reset brute-force tracker
            
                if(!$stmt->execute()) {
                    echo "Error: " . $stmt->error;
                }
            
                header("Location: ./logout.inc.php");
                exit();
            }
            }
        } 
    }
