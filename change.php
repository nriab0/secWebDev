<?php
    require_once 'functions.php';
    require_once 'csrf.php';
    include_once 'header.php';

    if (!isset($_SESSION['u_uid'])) {
        header("Location: ../index.php");
        exit();
    }
?>


<section class="main-container">
    <div class="main-wrapper">
        <h2>Change Password</h2>
        <br>
        
        <br>
        Please ensure your new password conforms to the complexity rules:
        <br>
        • Be at least 8 characters long<br>
        • Contain a mix of uppercase and lowercase<br>
        • Contain a digit<br>
        <form class="signup-form" action="includes/reset.inc.php" method="POST">
            <!-- [Password Complexity 10.4: Enforced via pattern attribute] -->
            <input type="password" name="old" value="" placeholder="Old Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>
            <input type="password" name="new" value="" placeholder="New Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>
            <input type="password" name="new_confirm" value="" placeholder="Confirm New Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>

            <!-- [CSRF 4.4: Embedding the token in the form] -->
            <?php echo csrf_input(); ?>

            <button type="submit" name="reset" value="yes">Reset</button>
        </form>
    </div>
</section>

<?php
    include_once 'footer.php';
?>
