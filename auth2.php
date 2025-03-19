<?php
	require_once 'functions.php';
	require_once 'csrf.php';
	include_once 'header.php';


	if (!isset($_SESSION['u_id'])) {
	header("Location: home.php");
	} else {
		$user_id = $_SESSION['u_id'];
		$user_uid = $_SESSION['u_uid'];
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 2</h2>
				<?php

// Validate Allowed File Names (Prevent XSS & Directory Traversal)
				$allowedFiles = ['yellow.txt', 'log.txt', 'rules.txt'];

// the file is volotile and required HTML escaping
				$ViewFile = escapeSTR($_GET['FileToView']);

				if (!in_array($ViewFile, $allowedFiles)) {
					die("Unauthorized file access.");
				}
     
				if(file_get_contents ("$ViewFile"))    
				{
				$FileData = file_get_contents ("$ViewFile");
				echo escapeSTR($FileData);
				}
				else
				{
				echo "no file found";
				}
?>
            </div>
        </section>

<?php
	include_once 'footer.php';
?>