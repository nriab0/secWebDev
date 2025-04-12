<?php
    require_once 'functions.php';
    require_once 'csrf.php';
    include_once 'dbh.inc.php';



        if (isset($_POST['submit'])) {    
            
            // [CSRF 4.4: Validate the token]
            csrf_validate();  

// [Brute Force 5.4: Check if user is locked out for repeated failures (like from login attempts)]
// e.g. check the 'failedLogins' table for IP

// Validate Username (Only Letters, Length 3-20)
        if (!preg_match('/^[a-zA-Z]{3,20}$/', $uid)) {
            $_SESSION['register'] = "Invalid username format.";
            header("Location: ../index.php");
            exit();
        }

// Since the sumbitted username is reflrected back to the user, it must be sanitized to prevent XSS

        $uid = sanitizeInput($_POST['uid']);
        $pwd = sanitizeInput($_POST['pwd']); 

        // [Password Complexity 10.4: Checking with regex for uppercase, lowercase, digit, length >= 8]
        if (!preg_match('/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/', $pwd)) {
            $_SESSION['register'] = "Password must be at least 8 characters, include uppercase, lowercase, and a digit.";
            header("Location: ../index.php");
            exit();
        }
        

        if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
        } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
        }
          else {
            $ipAddr=$_SERVER['REMOTE_ADDR'];
        }

        // [SQL Injection 3.4: Using prepared statements to check if user exists and insert]
        $checkClient = "SELECT failedLoginCount, timeStamp FROM failedLogins WHERE ip = ?";
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            $time = strtotime($row['timeStamp']);
            $now = time();
            $diff = $now - $time;
        
            if ($row['failedLoginCount'] >= 5 && $diff <= 180) {
                $_SESSION['register'] = "You are temporarily locked out due to multiple failed actions.";
                header("Location: ../index.php");
                exit();
            }
        }
        
        // Check for empty fields
        if (empty($uid) || empty($pwd)) {
            $_SESSION['register'] = "Cannot submit empty username or password.";
            header("Location: ../index.php");
            exit();

        } else {

            //Check to make sure only alphabetical characters are used for the username
            if (!preg_match("/^[a-zA-Z]*$/", $uid)) {

                $_SESSION['register'] = "Username must only contain alphabetic characters.";
                header("Location: ../index.php");
                exit();

            } else {
				
                    $sql = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("s", $uid);
                    $stmt->execute();
                    $result = $stmt->get_result();

					//If the user already exists, prevent them from signing up
                    if ($result->num_rows > 0) {

                        $_SESSION['register'] = "Error.";
                        header("Location: ../index.php");
                        exit();

                    } else {
                        // [Password Storage 9.4: Salt + SHA-256 hashing before INSERT]
                        // Hash the password with a random salt
                        // Use a secure hashing algorithm (e.g., bcrypt, Argon2) for better security
                        
                        $salt = bin2hex(random_bytes(16));      // random salt
                        $salted = $salt . $pwd;                                 // e.g. ab12cd + PlainTextPassword
                        $hashedPWD = hash('sha256', $salted);

                        $sql = "INSERT INTO `sapusers` (`user_uid`, `user_pwd`, `user_salt`) VALUES (?, ?, ?)";
                        $stmt = $conn->prepare($sql);
                        $stmt->bind_param("sss", $uid, $hashedPWD, $salt);
                        
                        if(!$stmt->execute()) {
                            echo "Error: " . $stmt->error;
                        }

                        $_SESSION['register'] = "You've successfully registered as " . $uid . ".";

                        header("Location: ../index.php");
                        exit();

                    }
                }   
        }
    }