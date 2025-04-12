<?php
    include_once 'header.php';
    require_once 'csrf.php';
?>

    <section class="main-container">
        <div class="main-wrapper">
            <h2>Signup</h2>
            Please note your username must only contain alphabetic characters.
            <br><br>
			Please ensure your password conforms to the complexity rules:
			<br><br>
			• Be at least 8 characters long<br>
			• Contain a mix of uppercase and lowercase<br>
			• Contain a digit<br>
            <form class="signup-form" action="includes/signup.inc.php" method="POST">
                <input type="text" name="uid" placeholder="Username" pattern="[a-zA-Z]{3,20}" required>
                <input type="password" name="pwd" value="" placeholder="Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>

                <!-- [Mitigation for CSRF 4.4: Embedding a unique token in the signup form] -->
                <?= csrf_input(); ?>

                <button type="submit" name="submit">Register now</button>
            </form>
        </div>
    </section>

<?php
    include_once 'footer.php';
?>
