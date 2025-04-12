<?php
	require_once 'functions.php';
	require_once 'csrf.php';
	include_once 'header.php';


	if (!isset($_SESSION['u_id'])) {
	header("Location: home.php");
	exit();
	} else {
		$user_id = $_SESSION['u_id']; 
		$user_uid = $_SESSION['u_uid'];
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 1</h2>
				Only authenticated users should be able to see this Page(1).
            </div>
        </section>
	
<?php	
	echo "<br>";
	//Reflect user's name on the page
	if(isset($_SESSION['u_id'])) {
		$user_uid = $_SESSION['u_uid'];
		echo "You're logged in as " . escapeSTR($user_uid);
	}

// clearChar function removed in favour of my stronger escapeSTR function
?>

<html>

<!-- https://hackersonlineclub.com/command-injection-cheatsheet/

Objectives
1. Obtain the directory structure on the server
2. obtain the network configuration of the server
3. Upload a file that will execuite on the server (.php file parhaps)
4. Run the file -->

<head>

</head>


<div class="header">

</div>

<div class="clearfix">
  <div class="column menu">

  </div>

  <div class="column content">
	<p></p>


  </div> 
  
  <div class="column content">
  <p><br>Enter your IP/host to ping.  
            <form method='get' action=''>
                <div class="form-group"> 
                    <label></label>
                    <input class="form-control" width="50%" placeholder="" name="target"></input> <br>
                    <div align="left"> <button class="btn btn-default" type="submit">Submit Button</button></div>
               </div> 
            </form>
	</p>

  <?php
// escapeshellarg() is used to escape any characters in the string that might be used to trick the shell into executing arbitrary commands.
// It adds single quotes around the string and escapes any single quotes within the string with a backslash.
	try {
// [Command Injection 12.4: Using escapeshellarg() to safely pass user input to ping]
// Also XSS escaping the output with htmlspecialchars()
			if (isset($_REQUEST['target'])) {
				$target = $_REQUEST['target'];
				// Safely escape the argument
				$safeTarget = escapeshellarg($target);
		
				// Build the command with the escaped argument
				if (stristr(php_uname('s'), 'Windows NT')) {
					$cmd = "ping " . $safeTarget;
				} else {
					$cmd = "ping -c 3 " . $safeTarget;
				}
		
				$output = shell_exec($cmd);
				echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
			}
		}
	catch(Exception $e) {
		echo '<BR> Pass your payload to a parameter called name on the URL (HTTP GET request) ';
		echo '<BR><p><b>Example:</b>    http://localhost/Lab/dt/dt.php?target=IPaddress </p>';	
	}

	?>
	</div>
	
</div>

<div class="footer">
</div>

</body>
</html>



