<?php
      require_once 'functions.php';
      include_once 'header.php';
	include_once 'includes/dbh.inc.php';

		//Validation here to prevent normal user from accessing directly
      if (!isset($_SESSION['u_id']) || $_SESSION['u_admin'] == 0) {
            
      } else {
            $user_id = $_SESSION['u_id'];
            $user_uid = $_SESSION['u_uid'];
      }
?>

      <section class="main-container">
            <div class="main-wrapper">
                  <h2>Login Events</h2>
                  <div class="admin-entry-count">
                        <?php
                              $entry_total_result = mysqli_query($conn, "SELECT count(event_id) AS num_rows FROM loginevents");
                              $row = mysqli_fetch_object($entry_total_result);
                              $total = $row->num_rows;
                        ?>
                        <p><i>Total entry count: <?php echo escapeSTR($total); ?></i></p>
                  </div>
                  <?php

                        $query = mysqli_query($conn, "SELECT * FROM loginevents");
                        while ($row = mysqli_fetch_array($query)) {
                              $id = $row['event_id'];
                              $ipAddr = $row['ip'];
                              $time = $row['timeStamp'];
                              $user_id = $row['user_id'];
                              $outcome = $row['outcome'];

                              echo "<div class='admin-content'>
                                          Entry ID: <b>'" . escapeSTR($id) . "'</b>
                                          <br>
                                          <form class='admin-form' method='GET'>
                                                <label>IP Address: </label><input type='text' name='IP' value='" . escapeSTR($ipAddr) . "'><br>
                                                <label>Timestamp: </label><input type='text' name='timestamp' value='" . escapeSTR($time) . "' ><br>
                                                <label>User ID: </label><input type='text' name='timestamp' value='" . escapeSTR($user_id) . "' ><br>
                                                <label>Outcome: </label><input type='text' name='timestamp' value='" . escapeSTR($outcome) . "' >
                                          </form>
                                          <br>
                                    </div>";
                        }
                  ?>
            </div>
      </section>
      <?php
            include_once 'footer.php';
      ?>
