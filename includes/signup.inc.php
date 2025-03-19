<?php
    require_once 'functions.inc.php';
    require_once 'csrf.php';
    include_once 'dbh.inc.php';



        if (isset($_POST['submit'])) {    
        

// Validate Username (Only Letters, Length 3-20)
        if (!preg_match('/^[a-zA-Z]{3,20}$/', $uid)) {
            $_SESSION['register'] = "Invalid username format.";
            header("Location: ../index.php");
            exit();
        }

// Since the sumbitted username is reflrected back to the user, it must be sanitized to prevent XSS
        $uid = escapeSTR($_POST["uid"]);

        $pwd = $_POST['pwd'];

        if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
        } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
        }
          else {
            $ipAddr=$_SERVER['REMOTE_ADDR'];
        }

        //CHECK IF USER IS LOCKED OUT
        $checkClient = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?";
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result(); 
        if ($result->fetch_row()[0] == 5) {
            $_SESSION['register'] = "Error: locked out.";
            header("Location: ../index.php");
            exit();
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
                        $hashedPWD = $pwd;

                        $sql = "INSERT INTO `sapusers` (`user_uid`, `user_pwd`) VALUES (?, ?)"; 
                        $stmt = $conn->prepare($sql);
                        $stmt->bind_param("ss", $uid, $hashedPWD);
                        
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