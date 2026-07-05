<?php
$conn = new mysqli("localhost", "root", "", "medic_vault_db");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>