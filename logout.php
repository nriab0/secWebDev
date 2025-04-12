    <?php
        require_once 'functions.php';
        require_once 'csrf.php';
        include_once 'header.php';

        if (isset($_SESSION['u_id'])) {
             // [Session Management 7.4: Properly destroying session data upon logout]
            session_unset();
            session_destroy();
            session_start(); // Re-init so you can show feedback messages
        }
    ?>

        <section class="main-container">
            <div class="main-wrapper">
                <h2>Successful Logout</h2>

                <?php
                    if (!isset($_SESSION['u_id'])) {
                        echo "You are now logged out!";
                    }

                    if(isset($_SESSION['resetSuccess'])) {
						echo escapeSTR($_SESSION['resetSuccess']);
						unset($_SESSION['resetSuccess']);
					}
                ?>
            </div>
        </section>

    <?php
        include_once 'footer.php';
    ?>
