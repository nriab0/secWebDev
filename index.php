<?php
      require_once 'functions.php';
	  require_once 'csrf.php';
	  include_once 'header.php';
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Homepage</h2>
				Welcome to this Super Secure PHP Application.
				<form method="post" action="">
    				<!-- [Mitigation for CSRF 4.4: Embedding a token to protect DB creation button] -->
					<?php echo csrf_input(); ?> 
    
    				<input type="submit" name="createDatabase" value="Create / Reset Database & Table">
				</form>
		<?php

				//DATABASE SETUP
				    $host = "localhost";
					$username = "TEST";
					$password = "";
					
					echo "<br>";
				
					
		if (isset($_POST['createDatabase'])) {
			// [CSRF 4.4: validating token in your code below -> csrf_validate();]
			csrf_validate();
        try {
            // Connect to MySQL server
            $conn = new PDO("mysql:host=$host", $username, $password);

            // Set the PDO error mode to exception
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

			$existingDatabases = $conn->query("SHOW DATABASES")->fetchAll(PDO::FETCH_COLUMN);
            echo "<br>";
                                                
            if (!in_array('secureappdev', $existingDatabases)) {
                // Create a new database
                $sql = "CREATE DATABASE secureappdev";
                $conn->exec($sql);
                echo "Database created successfully<br>";
                $sql = "USE secureappdev";
                $conn->exec($sql);
                
				//added salt to password hashing
				$makeUsers = "CREATE TABLE `sapusers` 
				(
					`user_id` INT(11) NOT NULL AUTO_INCREMENT,
					user_uid  VARCHAR(256) NOT NULL,
					user_pwd  VARCHAR(256) NOT NULL,       -- the hashed password
					user_salt VARCHAR(64)  NOT NULL,       -- store the random salt here
					user_admin INT(2) NOT NULL DEFAULT 0,
					PRIMARY KEY (`user_id`)
				)";
				
				$conn->exec($makeUsers);
				echo "Table 'users' created successfully<br>"; 



				 // [Password Storage 9.4: Generating salt and hashing in "saltAndHash()" for initial admin user]
				function saltAndHash($plain) {
					$salt = bin2hex(random_bytes(16));          // generate random salt (32 hex chars)
					$salted = $salt . $plain;                   				// concatenate
					$hashed = hash('sha256', $salted);           	// sha256 hash
					return [$salt, $hashed];
				}

				// 2 Admin
				list($adminSalt, $adminHash) = saltAndHash('AdminPass1!');
				$makeAdmin = "INSERT INTO sapusers (user_uid, user_pwd, user_salt, user_admin)
							VALUES ('admin', '$adminHash', '$adminSalt', '1')";
				$conn->exec($makeAdmin);
				echo "Admin Added (Username=admin, Password=AdminPass1!)<br>";

				// 3 user1
				list($userSalt, $userHash) = saltAndHash('Password1!');
				$makeUser = "INSERT INTO sapusers (user_uid, user_pwd, user_salt, user_admin)
							VALUES ('user1', '$userHash', '$userSalt', '0')";
				$conn->exec($makeUser);
				echo "User Added (Username=user1, Password=Password1!)<br>";
				
				//Make table to track pre-auth sessions that should be blocked for failed login attempts
				$makeCounter = "CREATE TABLE `failedLogins`
				(
					`event_id` int(11) NOT NULL AUTO_INCREMENT,
					`ip` varchar(128) NOT NULL,
					`timeStamp` datetime NOT NULL,
					`failedLoginCount` int(11) NOT NULL,
					`lockOutCount` int(11) NOT NULL,
					primary key (`event_id`)
				)";
				$conn->exec($makeCounter);
				
				$loginEvents = "CREATE TABLE `loginEvents`
				(
				`event_id` int(11) NOT NULL AUTO_INCREMENT,
				`ip` varchar(128) NOT NULL,
				`timeStamp` datetime NOT NULL,
				`user_id` varchar(50) NOT NULL,
				`outcome` varchar(7) NOT NULL,
				primary key (`event_id`)
				)";
				$conn->exec($loginEvents);
			}

        } catch (PDOException $e) {
            echo "Error: " . escapeSTR($e->getMessage());
			// [Reflective XSS 1.4 / 2.4: Using escapeSTR() on the error message so no HTML/JS runs]
        }

        $conn = null; // Close the database connection
    }
	
					
					//Message if login fails 
					echo "<br>";
					if (isset($_SESSION['failedMsg']))
					{
						echo escapeSTR($_SESSION['failedMsg']);
						unset($_SESSION['failedMsg']);
					}

					//Message if locked out 
					if(isset($_SESSION['lockedOut'])) {
						echo escapeSTR($_SESSION['lockedOut']);
						unset($_SESSION['lockedOut']);
					}

					//Remaining seconds for current lockout
					if(isset($_SESSION['timeLeft'])) {
						echo escapeSTR(" (" . $_SESSION['timeLeft'] . " seconds remaining).");
						unset($_SESSION['timeLeft']);
					}

					//Print messages re: registration
					if(isset($_SESSION['register'])) {
						echo escapeSTR($_SESSION['register']);
						unset($_SESSION['register']);
					}

					//Print messages re: changing password
					if(isset($_SESSION['resetError'])) {
						echo escapeSTR($_SESSION['resetError']);
						unset($_SESSION['resetError']);
					}
                ?>
				
            </div>
        </section>

<?php
	include_once 'footer.php';
?>