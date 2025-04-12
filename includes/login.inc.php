<?php
session_start();    
require_once 'functions.php';
require_once 'csrf.php';
include 'dbh.inc.php';


if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
    $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
} elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
}
  else {
    $ipAddr=$_SERVER['REMOTE_ADDR'];
}


if (isset($_POST['submit'])) {
    // [CSRF 4.4: Validate token on login form submission]
    csrf_validate();    

// [Brute Force 5.4: Checking 'failedLogins' table, limiting attempts, lockouts for 3 minutes]
    // logic around `failedLoginCount`, timestamps, etc.

// Validate Username Format (Only Letters, 3-20 Characters)
    if (!preg_match('/^[a-zA-Z]{3,20}$/', $_POST['uid'])) {
        $_SESSION['failedMsg'] = "Invalid username format.";
        header("Location: ../index.php");
        exit();
    }

// Prevent XSS in Username and ip address for suppurfluos security
    $uid = sanitizeInput($_POST['uid']);
    $pwd = $_POST['pwd'];
    $ipAddr = escapeSTR($ipAddr);

        // [SQL Injection 3.4: Using prepared statements for user lookups]
    $checkClient = "SELECT `failedLoginCount`, `timeStamp` FROM `failedLogins` WHERE `ip` = ?";
    $stmt = $conn->prepare($checkClient);
    $stmt->bind_param("s", $ipAddr);
    $stmt->execute();
    $result = $stmt->get_result(); 
    $time = date("Y-m-d H:i:s");

    //New user, insert into database and login
    //"Initialise" attempts recording their IP, timestamp and setup a failed login count, based off IP and attempted uid
    if ($result->num_rows == 0) {

        $addUser = "INSERT INTO `failedLogins` (`ip`, `timeStamp`, `failedLoginCount`, `lockOutCount`) VALUES (?, ?, '0', '0')"; //'$ipAddr', '$time'
        $stmt = $conn->prepare($addUser);
        $stmt->bind_param("ss", $ipAddr, $time);

        if(!$stmt->execute()) {
            die("Error: " . $stmt->error);
        }

        processLogin($conn,$uid,$pwd,$ipAddr);
        
        //Handle subsequent visits for each client
    } else {
        $getCount = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?"; //$ipAddr
        $stmt = $conn->prepare($getCount);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result();

            if (!$result) {
                die("Error: " . $stmt->error);
            } else { 
                //Assign count in variable so we can compare it for each failed login
                $failedLoginCount = ($result->fetch_row()[0]);

                if ($failedLoginCount >= 5) {
                    //Assuming theres 5 failed logins from this IP now check the timestamp to lock them out for 3 minutes
                    $checkTime = "SELECT `timeStamp` FROM `failedLogins` WHERE `ip` = ?"; //$ipAddr
                    $stmt = $conn->prepare($checkTime);
                    $stmt->bind_param("s", $ipAddr);
                    $stmt->execute();
                    $result = $stmt->get_result();

                    if(!$result) {
                        die('Error: ' . $stmt->error);
                    } else {
                        $failedLoginTime = ($result->fetch_row()[0]);
                    }

                    $currTime = date("Y-m-d H:i:s");
                    $timeDiff = abs(strtotime($currTime) - strtotime($failedLoginTime));
                    $_SESSION['timeLeft'] = 180 - $timeDiff; //Print to inform user of how many seconds remain on the lockout

                    if((int)$timeDiff <= 180) {
                        $_SESSION['lockedOut'] = "Due to multiple failed logins you're now locked out, please try again in 3 minutes"; //Should also stop user if they try to register

                        //Store unsuccessful login attempt, uid, timestamp, IP in log format for viewing at admin.php
                        $time = date("Y-m-d H:i:s");
                        $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'fail')"; //$ipAddr, $time, $uid
                        $stmt = $conn->prepare($recordLogin);
                        $stmt->bind_param("sss", $ipAddr, $time, $uid);
                        $stmt->execute();

                        if(!$stmt->execute()) {
                            die("Errory: " . $stmt->error);
                        }
                        //Redirect given lockout is currently enabled
                        header("location: ../index.php");
                        
                    } else {

                        //Update lockOutCount
                        $updateLockOutCount = "UPDATE `failedLogins` SET `lockOutCount` = `lockOutCount` + 1 WHERE `ip` = ?"; //$ipAddr
                        $stmt = $conn->prepare($updateLockOutCount);
                        $stmt->bind_param("s", $ipAddr);

                        if(!$stmt->execute()) {
                            die("Errorz: " . $stmt->error);
                        } else {

                            //Otherwise update the lockout counter/timestamp
                            $currTime = date("Y-m-d H:i:s");
                            $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = '0', `timeStamp` = ? WHERE `ip` = ?"; //$currTime, $ipAddr
                            $stmt = $conn->prepare($updateCount);
                            $stmt->bind_param("ss", $currTime, $ipAddr);

                            if(!$stmt->execute()) {
                                die("Error: " . $stmt->error);
                            }
                            
                            processLogin($conn,$uid,$pwd,$ipAddr); 
                        }
                    }
                    
                } else {
                    processLogin($conn,$uid,$pwd,$ipAddr);
                }
            }
    }
}

function processLogin($conn, $uid, $pwd, $ipAddr) {
    // Check if inputs are empty
    if (empty($uid) || empty($pwd)) {
        header("Location: ../index.php?login=empty");
        failedLogin($uid, $ipAddr);
        exit();
    } else {
        // Use a parameterized query to securely fetch user data
        $sql = "SELECT * FROM sapusers WHERE user_uid = ?";
        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            die("Error preparing statement: " . $conn->error);
        }
     
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows < 1) {
            failedLogin($uid, $ipAddr);
        } else {
            if ($row = $result->fetch_assoc()) {
                // [Password Storage 9.4: Checking the stored salt+hash combination]
                    // 1. Retrieve the user_salt and user_pwd from the row
                    $saltFromDB   = $row['user_salt'];  // a hex string
                    $storedHash   = $row['user_pwd'];   // the SHA-256 hex digest

                    // 2. Rebuild the salted + hashed password from user input
                    $computedHash = hash('sha256', $saltFromDB . $pwd);

                    // 3. Compare
                    if ($computedHash !== $storedHash) {
                        // mismatch => password is incorrect
                        failedLogin($uid, $ipAddr);
                    } else {
                        // match => success
                         // [Session Fixation 8.4: session_regenerate_id(true) after successful login]
                        session_regenerate_id(true);

                        $_SESSION['u_id'] = $row['user_id'];
                        $_SESSION['u_uid'] = $row['user_uid'];
                        $_SESSION['u_admin'] = $row['user_admin'];

                        // Log event, redirect, etc.
                        $time = date("Y-m-d H:i:s");
                        $recordLogin = "INSERT INTO loginEvents (ip, timeStamp, user_id, outcome) VALUES (?, ?, ?, 'success')";
                        $stmtLog = $conn->prepare($recordLogin);
                        $stmtLog->bind_param("sss", $ipAddr, $time, $uid);
                        $stmtLog->execute();

                        header("Location: ../auth1.php");
                        exit();
                    }
                }
            }
        }
    }

function failedLogin ($uid,$ipAddr) {
    include "dbh.inc.php";
    //When login fails redirect to index and set the failedMsg variable so it can be displayed on index
    $_SESSION['failedMsg'] = "The username " . escapeSTR($uid) . " and password could not be authenticated at this moment.";
    
    //Store unsuccessful login attempt, uid, timestamp, IP in log format for viewing at admin.php
    $time = date("Y-m-d H:i:s");
    $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'fail')"; //$ipAddr, $time, $uid
    $stmt = $conn->prepare($recordLogin);
    $stmt->bind_param("sss", $ipAddr, $time, escapeSTR($uid));

    if(!$stmt->execute()) {
        die("Error 1: " . $stmt->error);
    } else {
        //Update failed login count for client
        $currTime = date("Y-m-d H:i:s");
        $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?"; //$currTime, $ipAddr
        $stmt = $conn->prepare($updateCount);
        $stmt->bind_param("ss", $currTime, $ipAddr);

        if(!$stmt->execute()) {
            die("Error 2: " . $stmt->error);
        } else {
            header("Location: ../index.php");
            exit();
        }
    }
    
}
